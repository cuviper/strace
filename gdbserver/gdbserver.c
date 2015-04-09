/* Implementation of strace features over the GDB remote protocol.
 *
 * Copyright (c) 2015 Red Hat Inc.
 * Copyright (c) 2015 Josh Stone <cuviper@gmail.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#define _GNU_SOURCE 1
#include <stdlib.h>
#include <sys/wait.h>

#include "defs.h"
#include "gdbserver.h"
#include "protocol.h"
#include "signals.h"

char* gdbserver = NULL;
static struct gdb_conn* gdb = NULL;

enum gdb_stop {
        gdb_stop_unknown, // O or F or anything else
        gdb_stop_error, // E
        gdb_stop_signal, // S or T
        gdb_stop_exited, // W
        gdb_stop_terminated, // X

        // specific variants of gdb_stop_signal 05
        gdb_stop_trap, // missing or unrecognized stop reason
        gdb_stop_syscall_entry,
        gdb_stop_syscall_return,
};


struct gdb_stop_reply {
        char *reply;
        size_t size;

        enum gdb_stop type;
        int code; // error, signal, exit status, scno
        int pid; // process id, aka kernel tgid
        int tid; // thread id, aka kernel tid
};

static void
gdb_recv_signal(struct gdb_stop_reply *stop)
{
        char *reply = stop->reply;

        stop->code = gdb_decode_hex_n(&reply[1], 2);
        stop->type = stop->code == GDB_SIGNAL_TRAP ?
                gdb_stop_trap : gdb_stop_signal;

        // tokenize the n:r pairs
        char *info = strdupa(reply + 3);
        char *savetok, *nr;
        for (nr = strtok_r(info, ";", &savetok); nr;
                        nr = strtok_r(NULL, ";", &savetok)) {
                char *n = strtok(nr, ":");
                char *r = strtok(NULL, "");
                if (!n || !r)
                        continue;

                if (!strcmp(n, "thread")) {
                        if (*r == 'p') {
                                // pPID or pPID.TID
                                ++r;
                                stop->pid = gdb_decode_hex_str(r);

                                // stop messages should always have the TID,
                                // but if not, just use the PID.
                                char *dot = strchr(r, '.');
                                if (!dot) {
                                        stop->tid = stop->pid;
                                } else {
                                        stop->tid = gdb_decode_hex_str(dot + 1);
                                }
                        } else {
                                // just TID, assume same PID
                                stop->tid = gdb_decode_hex_str(r);
                                stop->pid = stop->tid;
                        }
                }
                else if (!strcmp(n, "syscall_entry")) {
                        if (stop->type == gdb_stop_trap) {
                                stop->type = gdb_stop_syscall_entry;
                                stop->code = gdb_decode_hex_str(r);
                        }
                }
                else if (!strcmp(n, "syscall_return")) {
                        if (stop->type == gdb_stop_trap) {
                                stop->type = gdb_stop_syscall_return;
                                stop->code = gdb_decode_hex_str(r);
                        }
                }
        }

        // TODO guess architecture by the size of reported registers?
}

static void
gdb_recv_exit(struct gdb_stop_reply *stop)
{
        char *reply = stop->reply;

        stop->type = reply[0] == 'W' ?
                gdb_stop_exited : gdb_stop_terminated;
        stop->code = gdb_decode_hex_str(&reply[1]);

        const char *process = strstr(reply, ";process:");
        if (process) {
                stop->pid = gdb_decode_hex_str(process + 9);

                // we don't really know the tid, so just use PID for now
                // XXX should exits enumerate all threads we know of a process?
                stop->tid = stop->pid;
        }
}

static struct gdb_stop_reply
gdb_recv_stop()
{
        struct gdb_stop_reply stop = {
                .reply = NULL,
                .size = 0,

                .type = gdb_stop_unknown,
                .code = -1,
                .pid = -1,
                .tid = -1,
        };

        stop.reply = gdb_recv(gdb, &stop.size);

        // all good packets are at least 3 bytes
        switch (stop.size >= 3 ? stop.reply[0] : 0) {
                case 'E':
                        stop.type = gdb_stop_error;
                        stop.code = gdb_decode_hex_n(stop.reply + 1, 2);
                        break;
                case 'S':
                case 'T':
                        gdb_recv_signal(&stop);
                        break;
                case 'W':
                case 'X':
                        gdb_recv_exit(&stop);
                        break;
                default:
                        stop.type = gdb_stop_unknown;
                        break;
        }

        return stop;
}

static bool
gdb_ok()
{
        size_t size;
        char *reply = gdb_recv(gdb, &size);
        bool ok = size == 2 && !strcmp(reply, "OK");
        free(reply);
        return ok;
}

void
gdb_init()
{
        // FIXME error checking...
        const char *addr = strtok(gdbserver, ":");
        uint16_t port = atoi(strtok(NULL, ""));
        gdb = gdb_begin_inet(addr, port);

        if (!gdb_start_noack(gdb))
                error_msg("couldn't enable gdb noack mode");

        static const char multi_cmd[] = "qSupported:multiprocess+";
        gdb_send(gdb, multi_cmd, sizeof(multi_cmd) - 1);

        size_t size;
        char *reply = gdb_recv(gdb, &size);
        if (!strstr(reply, "multiprocess+"))
                error_msg("couldn't enable gdb multiprocess mode");
        free(reply);

        static const char extended_cmd[] = "!";
        gdb_send(gdb, extended_cmd, sizeof(extended_cmd) - 1);
        if (!gdb_ok())
                error_msg("couldn't enable gdb extended mode");

        static const char syscall_cmd[] = "QCatchSyscalls:1";
        gdb_send(gdb, syscall_cmd, sizeof(syscall_cmd) - 1);
        if (!gdb_ok())
                error_msg("couldn't enable gdb syscall catching");
}

void
gdb_finalize_init()
{
        // TODO Should we enumerate all attached threads to be sure?
        // Especially since we get all threads on vAttach, not just the one pid.
        // qfThreadInfo [qsThreadInfo]...
        // or qXfer:threads:read::offset,length

        // XXX valgrind doesn't support vCont, which can be determined by an
        // empty reply from probing "vCont?" at startup.  It likewise doesn't
        // report multiprocess in qSupported.  Use plain c/Cxx in that case.

        // Everything was stopped from startup_child/startup_attach,
        // now continue them all so the next reply will be a stop packet
        static const char cmd[] = "vCont;c";
        gdb_send(gdb, cmd, sizeof(cmd) - 1);
}

void
gdb_cleanup()
{
        if (gdb)
                gdb_end(gdb);
        gdb = NULL;
}

void
gdb_startup_child(char **argv)
{
        if (!gdb)
                error_msg_and_die("gdb server not connected!");

        size_t i;
        size_t size = 4; // vRun
        for (i = 0; argv[i]; ++i) {
                size += 1 + 2 * strlen(argv[i]); // ;hexified-argument
        }

        char *cmd = malloc(size);
        if (!cmd)
                error_msg_and_die("malloc failed!");
        char *cmd_ptr = cmd;
        memcpy(cmd_ptr, "vRun", 4);
        cmd_ptr += 4;
        for (i = 0; argv[i]; ++i) {
                *cmd_ptr++ = ';';
                const char *arg = argv[i];
                while (*arg) {
                        gdb_encode_hex(*arg++, cmd_ptr);
                        cmd_ptr += 2;
                }
        }

        gdb_send(gdb, cmd, size);
        free(cmd);

        struct gdb_stop_reply stop = gdb_recv_stop();
        if (stop.size == 0)
                error_msg_and_die("gdb server doesn't support vRun!");
        switch (stop.type) {
                case gdb_stop_error:
                        error_msg_and_die("gdb server failed vRun with %.*s",
                                        (int)stop.size, stop.reply);
                case gdb_stop_trap:
                        break;
                default:
                        error_msg_and_die("gdb server expected vRun trap, got: %.*s",
                                        (int)stop.size, stop.reply);
        }

        pid_t tid = stop.tid;
        free(stop.reply);

        strace_child = tid;

	struct tcb *tcp = alloctcb(tid);
        tcp->flags |= TCB_ATTACHED | TCB_STARTUP;
        newoutf(tcp);

        // TODO normal strace attaches right before exec, so the first syscall
        // seen is the execve with all its arguments.  Need to emulate that here?
        hide_log_until_execve = 0;
}

void
gdb_startup_attach(struct tcb *tcp)
{
        char cmd[] = "vAttach;XXXXXXXX";
        sprintf(cmd, "vAttach;%x", tcp->pid);
        gdb_send(gdb, cmd, strlen(cmd));

        struct gdb_stop_reply stop = gdb_recv_stop();
        if (stop.size == 0)
                error_msg_and_die("gdb server doesn't support vAttach!");
        switch (stop.type) {
                case gdb_stop_error:
                        error_msg_and_die("gdb server failed vAttach with %.*s",
                                        (int)stop.size, stop.reply);
                case gdb_stop_trap:
                        break;
                case gdb_stop_signal:
                        if (stop.code == 0)
                                break;
                        // fallthrough
                default:
                        error_msg_and_die("gdb server expected vAttach trap, got: %.*s",
                                        (int)stop.size, stop.reply);
        }

        pid_t tid = stop.tid;
        free(stop.reply);

        if (tid != tcp->pid) {
                droptcb(tcp);
                tcp = alloctcb(tid);
        }
        tcp->flags |= TCB_ATTACHED | TCB_STARTUP;
        newoutf(tcp);

        if (!qflag)
                fprintf(stderr, "Process %u attached\n", tcp->pid);
}

void
gdb_detach(struct tcb *tcp)
{
        char cmd[] = "D;XXXXXXXX";
        sprintf(cmd, "D;%x", tcp->pid);
        gdb_send(gdb, cmd, strlen(cmd));

        if (!gdb_ok())
                error_msg("gdb server failed to detach %d", tcp->pid);
}

// Returns true iff the main trace loop has to continue.
// The gdb connection should be ready for a stop reply on entry,
// and we'll leave it the same way if we return true.
bool
gdb_trace()
{
        struct gdb_stop_reply stop = gdb_recv_stop();

        if (stop.size == 0)
                error_msg_and_die("gdb server gave an empty stop reply!?");
        switch (stop.type) {
                case gdb_stop_unknown:
                        error_msg_and_die("gdb server stop reply unknown: %.*s",
                                        (int)stop.size, stop.reply);
                case gdb_stop_error:
                        // vCont error -> no more processes
                        free(stop.reply);
                        return false;
                default:
                        break;
        }

        pid_t tid = stop.tid;
        if (tid < 0)
                error_msg_and_die("couldn't read tid from stop reply: %.*s",
                                (int)stop.size, stop.reply);

	/* Look up 'tid' in our table. */
	struct tcb *tcp = pid2tcb(tid);
	if (!tcp) {
                tcp = alloctcb(tid);
		tcp->flags |= TCB_ATTACHED | TCB_STARTUP;
		newoutf(tcp);
	}

        get_regs(tid);

        // TODO need code equivalent to PTRACE_EVENT_EXEC?

	/* Set current output file */
	current_tcp = tcp;

        /* Is this the very first time we see this tracee stopped? */
        if (tcp->flags & TCB_STARTUP) {
                tcp->flags &= ~TCB_STARTUP;
                if (get_scno(tcp) == 1)
                        tcp->s_prev_ent = tcp->s_ent;
        }

        // TODO cflag means we need to update tcp->dtime/stime
        // usually through wait rusage, but how can we do it?

        int gdb_sig = 0;
        switch (stop.type) {
                case gdb_stop_unknown:
                case gdb_stop_error:
                        // already handled above
                        break;

                case gdb_stop_trap:
                        // misc trap, nothing to do...
                        break;
                case gdb_stop_syscall_entry:
                case gdb_stop_syscall_return:
                        // should we make sure TCB_INSYSCALL is consistent?
                        tcp->scno = stop.code;
                        trace_syscall(tcp);
                        break;
                case gdb_stop_signal:
                        {
                                static const char cmd[] = "qXfer:siginfo:read::0,fff";
                                gdb_send(gdb, cmd, sizeof(cmd) - 1);

                                siginfo_t *si = NULL;
                                size_t siginfo_size;
                                char *siginfo_reply = gdb_recv(gdb, &siginfo_size);
                                if (siginfo_size == sizeof(siginfo_t) + 1
                                                && siginfo_reply[0] == 'l') {
                                        si = (siginfo_t *) &siginfo_reply[1];
                                }

                                // XXX gdbserver returns "native" siginfo of 32/64-bit target
                                // but strace expects its own format as PTRACE_GETSIGINFO
                                // would have given it.
                                // (i.e. need to reverse siginfo_fixup)
                                // ((i.e. siginfo_from_compat_siginfo))

                                // TODO need to translate gdb's signal numbers...
                                // (but the real one shows in the siginfo for now, anyway)
                                gdb_sig = stop.code;
                                print_stopped(tcp, si, gdb_sig);
                                free(siginfo_reply);
                        }
                        break;

                case gdb_stop_exited:
                        print_exited(tcp, tid, W_EXITCODE(stop.code, 0));
                        droptcb(tcp);
                        break;

                case gdb_stop_terminated:
                        // TODO need to translate gdb's signal numbers...
                        print_signalled(tcp, tid, W_EXITCODE(0, stop.code));
                        droptcb(tcp);
                        break;
        }

        free(stop.reply);

        // XXX valgrind doesn't support vCont, see gdb_finalize_init.
        if (gdb_sig) {
                // send the signal to this target and continue everyone else
                char cmd[] = "vCont;Cxx:xxxxxxxx;c";
                sprintf(cmd, "vCont;C%02x:%x;c", gdb_sig, tid);
                gdb_send(gdb, cmd, sizeof(cmd) - 1);
        } else {
                // just continue everyone
                static const char cmd[] = "vCont;c";
                gdb_send(gdb, cmd, sizeof(cmd) - 1);
        }
        return true;
}
