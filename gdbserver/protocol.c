/* Simple implementation of a GDB remote protocol client.
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
#include <err.h>
#include <fcntl.h>
#include <netdb.h>
#include <signal.h>
#include <spawn.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>

#include <netinet/in.h>

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>


#include "protocol.h"

struct gdb_conn {
    FILE *in;
    FILE *out;
    bool ack;
};


void gdb_encode_hex(uint8_t byte, char* out) {
    static const char value_hex[16] = {
        '0', '1', '2', '3', '4', '5', '6', '7',
        '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
    };
    *out++ = value_hex[byte >> 4];
    *out++ = value_hex[byte & 0xf];
}

static inline uint8_t
hex_nibble(uint8_t hex)
{
    static const uint8_t hex_value[256] = {
        [0 ... '0'-1] = UINT8_MAX,
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
        ['9'+1 ... 'A'-1] = UINT8_MAX,
        10, 11, 12, 13, 14, 15,
        ['F'+1 ... 'a'-1] = UINT8_MAX,
        10, 11, 12, 13, 14, 15,
        ['f'+1 ... 255] = UINT8_MAX,
    };
    return hex_value[hex];
}

uint16_t gdb_decode_hex(char msb, char lsb)
{
    uint8_t high_nibble = hex_nibble(msb);
    uint8_t low_nibble = hex_nibble(lsb);
    if (high_nibble >= 16 || low_nibble >= 16)
        return UINT16_MAX;
    return 16 * hex_nibble(msb) + hex_nibble(lsb);
}

uint64_t gdb_decode_hex_n(const char *bytes, size_t n)
{
    uint64_t value = 0;
    while (n--) {
        uint8_t nibble = hex_nibble(*bytes++);
        if (nibble >= 16)
            break;
        value = 16 * value + nibble;
    }
    return value;
}

uint64_t gdb_decode_hex_str(const char *bytes)
{
    uint64_t value = 0;
    while (*bytes) {
        uint8_t nibble = hex_nibble(*bytes++);
        if (nibble >= 16)
            break;
        value = 16 * value + nibble;
    }
    return value;
}

int gdb_decode_hex_buf(const char *bytes, size_t n, char *out)
{
    if (n & 1)
        return -1;

    while (n > 1) {
        uint16_t byte = gdb_decode_hex(bytes[0], bytes[1]);
        if (byte > UINT8_MAX)
            return -1;

        *out++ = byte;
        bytes += 2;
        n -= 2;
    }
    return 0;
}


static struct gdb_conn *
gdb_begin(int fd)
{
    struct gdb_conn *conn = calloc(1, sizeof(struct gdb_conn));
    if (conn == NULL)
        err(1, "calloc");

    conn->ack = true;

    // duplicate the handle to separate read/write state
    int fd2 = dup(fd);
    if (fd2 < 0)
        err(1, "dup");

    // open a FILE* for reading
    conn->in = fdopen(fd, "rb");
    if (conn->in == NULL)
        err(1, "fdopen");

    // open a FILE* for writing
    conn->out = fdopen(fd2, "wb");
    if (conn->out == NULL)
        err(1, "fdopen");

    // reset line state by acking any earlier input
    fputc('+', conn->out);
    fflush(conn->out);

    return conn;
}

struct gdb_conn *
gdb_begin_command(const char *command)
{
    int ret;
    int fds[2];
    pid_t pid;
    posix_spawn_file_actions_t file_actions;
    const char* sh = "/bin/sh";
    const char *const const_argv[] = {"sh", "-c", command, NULL};
    char *const *argv = (char *const *) const_argv;

    // Create a bidirectional "pipe", [0] for us and [1] for the command stdio.
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) < 0)
        err(1, "socketpair");

    if ((ret = posix_spawn_file_actions_init(&file_actions)))
        errx(1, "posix_spawn_file_actions_init: %s", strerror(ret));

    // Close our end in the child.
    if ((ret = posix_spawn_file_actions_addclose(&file_actions, fds[0])))
        errx(1, "posix_spawn_file_actions_addclose: %s", strerror(ret));

    // Copy the child's end to its stdout and stdin.
    if (fds[1] != STDOUT_FILENO) {
        if ((ret = posix_spawn_file_actions_adddup2(&file_actions, fds[1], STDOUT_FILENO)))
            errx(1, "posix_spawn_file_actions_adddup2: %s", strerror(ret));
        if ((ret = posix_spawn_file_actions_addclose(&file_actions, fds[1])))
            errx(1, "posix_spawn_file_actions_addclose: %s", strerror(ret));
    }
    if ((ret = posix_spawn_file_actions_adddup2(&file_actions, STDOUT_FILENO, STDIN_FILENO)))
        errx(1, "posix_spawn_file_actions_adddup2: %s", strerror(ret));

    // Spawn the actual command.
    if ((ret = posix_spawn(&pid, sh, &file_actions, NULL, argv, environ)))
        errx(1, "posix_spawn: %s", strerror(ret));

    // Cleanup.
    if ((ret = posix_spawn_file_actions_destroy(&file_actions)))
        errx(1, "posix_spawn_file_actions_destroy: %s", strerror(ret));
    close(fds[1]);

    // Avoid SIGPIPE when the command quits.
    signal(SIGPIPE, SIG_IGN);

    // initialize the rest of gdb on this handle
    return gdb_begin(fds[0]);
}

struct gdb_conn *
gdb_begin_tcp(const char *node, const char *service)
{
    // NB: gdb doesn't support IPv6 - should we?
    const struct addrinfo hints = {
        .ai_family = AF_UNSPEC,
        .ai_socktype = SOCK_STREAM,
    };

    struct addrinfo *result = NULL;
    int s = getaddrinfo(node, service, &hints, &result);
    if (s)
        errx(1, "getaddrinfo: %s", gai_strerror(s));

    int fd = -1;
    for (struct addrinfo *ai = result; ai; ai = ai->ai_next) {
        // open the socket and start the tcp connection
        fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0)
            continue;

        if (connect(fd, ai->ai_addr, ai->ai_addrlen) == 0)
            break;

        close(fd);
        fd = -1;
    }

    freeaddrinfo(result);
    if (fd < 0)
        err(1, "connect");

    // initialize the rest of gdb on this handle
    return gdb_begin(fd);
}

struct gdb_conn *
gdb_begin_path(const char *path)
{
    int fd = open(path, O_RDWR);
    if (fd < 0)
        err(1, "open");

    // initialize the rest of gdb on this handle
    return gdb_begin(fd);
}


void
gdb_end(struct gdb_conn *conn)
{
    fclose(conn->in);
    fclose(conn->out);
    free(conn);
}


static void
send_packet(FILE *out, const char *command, size_t size)
{
    // compute the checksum -- simple mod256 addition
    size_t i;
    uint8_t sum = 0;
    for (i = 0; i < size; ++i)
        sum += (uint8_t)command[i];

    // NB: seems neither escaping nor RLE is generally expected by
    // gdbserver.  e.g. giving "invalid hex digit" on an RLE'd address.
    // So just write raw here, and maybe let higher levels escape/RLE.

    fputc('$', out); // packet start
    fwrite(command, 1, size, out); // payload
    fprintf(out, "#%02x", sum); // packet end, checksum
    fflush(out);

    if (ferror(out))
        err(1, "send");
    else if (feof(out))
        errx(0, "send: Connection closed");
}

void
gdb_send(struct gdb_conn *conn, const char *command, size_t size)
{
    bool acked = false;
    do {
        send_packet(conn->out, command, size);

        if (!conn->ack)
            break;

        // look for '+' ACK or '-' NACK/resend
        acked = fgetc_unlocked(conn->in) == '+';
    } while (!acked);
}


static char *
recv_packet(FILE *in, size_t *ret_size, bool* ret_sum_ok)
{
    size_t i = 0;
    size_t size = 4096;
    char *reply = malloc(size);
    if (reply == NULL)
        err(1, "malloc");

    int c;
    uint8_t sum = 0;
    bool escape = false;

    // fast-forward to the first start of packet
    while ((c = fgetc_unlocked(in)) != EOF && c != '$');

    while ((c = fgetc_unlocked(in)) != EOF) {
        sum += (uint8_t)c;
        switch (c) {
            case '$': // new packet?  start over...
                i = 0;
                sum = 0;
                escape = false;
                continue;

            case '#': // end of packet
                sum -= c; // not part of the checksum
                {
                    uint8_t msb = fgetc_unlocked(in);
                    uint8_t lsb = fgetc_unlocked(in);
                    *ret_sum_ok = sum == gdb_decode_hex(msb, lsb);
                }
                *ret_size = i;

                // terminate it for good measure
                if (i == size) {
                    reply = realloc(reply, size + 1);
                    if (reply == NULL)
                        err(1, "realloc");
                }
                reply[i] = '\0';

                return reply;

            case '}': // escape: next char is XOR 0x20
                escape = true;
                continue;

            case '*': // run-length-encoding
                // The next character tells how many times to repeat the last
                // character we saw.  The count is added to 29, so that the
                // minimum-beneficial RLE 3 is the first printable character ' '.
                // The count character can't be >126 or '$'/'#' packet markers.

                if (i > 0) { // need something to repeat!
                    int c2 = fgetc_unlocked(in);
                    if (c2 < 29 || c2 > 126 || c2 == '$' || c2 == '#') {
                        // invalid count character!
                        ungetc(c2, in);
                    } else {
                        int count = c2 - 29;

                        // get a bigger buffer if needed
                        if (i + count > size) {
                            size *= 2;
                            reply = realloc(reply, size);
                            if (reply == NULL)
                                err(1, "realloc");
                        }

                        // fill the repeated character
                        memset(&reply[i], reply[i - 1], count);
                        i += count;
                        sum += c2;
                        continue;
                    }
                }
        }

        // XOR an escaped character
        if (escape) {
            c ^= 0x20;
            escape = false;
        }
        
        // get a bigger buffer if needed
        if (i == size) {
            size *= 2;
            reply = realloc(reply, size);
            if (reply == NULL)
                err(1, "realloc");
        }

        // add one character
        reply[i++] = c;
    }

    if (ferror(in))
        err(1, "recv");
    else if (feof(in))
        errx(0, "recv: Connection closed");
    else
        errx(1, "recv: Unknown connection error");
}

char *
gdb_recv(struct gdb_conn *conn, size_t *size)
{
    char *reply;
    bool acked = false;
    do {
        reply = recv_packet(conn->in, size, &acked);

        if (conn->ack) {
            // send +/- depending on checksum result, retry if needed
            fputc(acked ? '+' : '-', conn->out);
            fflush(conn->out);
            if (!acked)
                free(reply);
        }
    } while (conn->ack && !acked);

    return reply;
}

bool
gdb_start_noack(struct gdb_conn *conn)
{
    static const char cmd[] = "QStartNoAckMode";
    gdb_send(conn, cmd, sizeof(cmd) - 1);

    size_t size;
    char *reply = gdb_recv(conn, &size);
    bool ok = size == 2 && !strcmp(reply, "OK");
    free(reply);

    if (ok)
        conn->ack = false;
    return ok ? "OK" : "";
}

/* Read complete qXfer data, returned as binary with the size.
 * On error, returns NULL with size set to the error code.  */
char *
gdb_xfer_read(struct gdb_conn *conn,
        const char *object, const char *annex,
        /* out */ size_t *ret_size)
{
    size_t error = 0;
    size_t offset = 0;
    char *data = NULL;
    do {
        char *cmd;
        int cmd_size = asprintf(&cmd, "qXfer:%s:read:%s:%zx,%x",
                object ?: "", annex ?: "", offset, 0xfff /* XXX PacketSize */);
        if (cmd_size < 0) {
            break;
        }

        gdb_send(conn, cmd, strlen(cmd));
        free(cmd);

        size_t size;
        char *reply = gdb_recv(conn, &size);
        char c = reply[0];
        switch (c) {
            case 'm':
            case 'l':
                data = realloc(data, offset + size - 1);
                memcpy(data + offset, reply + 1, size - 1);
                free(reply);
                offset += size - 1;
                if (c == 'l') {
                    *ret_size = offset;
                    return data;
                }
                continue;
            case 'E':
                error = gdb_decode_hex_str(reply + 1);
                break;
        }
        free(reply);
        break;
    } while (0);

    free(data);
    *ret_size = error;
    return NULL;
}
