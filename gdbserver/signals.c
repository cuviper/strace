/* Signal translation functions adapted from gdb/linux-tdep.c: */

/* Target-dependent code for GNU/Linux, architecture independent.

   Copyright (C) 2009-2015 Free Software Foundation, Inc.

   This file is part of GDB.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

#include "signals.h"

/* This enum represents the signals' numbers on a generic architecture
   running the Linux kernel.  The definition of "generic" comes from
   the file <include/uapi/asm-generic/signal.h>, from the Linux kernel
   tree, which is the "de facto" implementation of signal numbers to
   be used by new architecture ports.

   For those architectures which have differences between the generic
   standard (e.g., Alpha), we define the different signals (and *only*
   those) in the specific target-dependent file (e.g.,
   alpha-linux-tdep.c, for Alpha).  Please refer to the architecture's
   tdep file for more information.

   ARM deserves a special mention here.  On the file
   <arch/arm/include/uapi/asm/signal.h>, it defines only one different
   (and ARM-only) signal, which is SIGSWI, with the same number as
   SIGRTMIN.  This signal is used only for a very specific target,
   called ArthurOS (from RISCOS).  Therefore, we do not handle it on
   the ARM-tdep file, and we can safely use the generic signal handler
   here for ARM targets.

   As stated above, this enum is derived from
   <include/uapi/asm-generic/signal.h>, from the Linux kernel
   tree.  */

enum
  {
    LINUX_SIGHUP = 1,
    LINUX_SIGINT = 2,
    LINUX_SIGQUIT = 3,
    LINUX_SIGILL = 4,
    LINUX_SIGTRAP = 5,
    LINUX_SIGABRT = 6,
    LINUX_SIGIOT = 6,
    LINUX_SIGBUS = 7,
    LINUX_SIGFPE = 8,
    LINUX_SIGKILL = 9,
    LINUX_SIGUSR1 = 10,
    LINUX_SIGSEGV = 11,
    LINUX_SIGUSR2 = 12,
    LINUX_SIGPIPE = 13,
    LINUX_SIGALRM = 14,
    LINUX_SIGTERM = 15,
    LINUX_SIGSTKFLT = 16,
    LINUX_SIGCHLD = 17,
    LINUX_SIGCONT = 18,
    LINUX_SIGSTOP = 19,
    LINUX_SIGTSTP = 20,
    LINUX_SIGTTIN = 21,
    LINUX_SIGTTOU = 22,
    LINUX_SIGURG = 23,
    LINUX_SIGXCPU = 24,
    LINUX_SIGXFSZ = 25,
    LINUX_SIGVTALRM = 26,
    LINUX_SIGPROF = 27,
    LINUX_SIGWINCH = 28,
    LINUX_SIGIO = 29,
    LINUX_SIGPOLL = LINUX_SIGIO,
    LINUX_SIGPWR = 30,
    LINUX_SIGSYS = 31,
    LINUX_SIGUNUSED = 31,

    LINUX_SIGRTMIN = 32,
    LINUX_SIGRTMAX = 64,
  };

/* Implementation of `gdbarch_gdb_signal_from_target', as defined in
   gdbarch.h.  This function is not static because it is exported to
   other -tdep files.  */

enum gdb_signal
linux_gdb_signal_from_target (/*struct gdbarch *gdbarch,*/ int signal)
{
  switch (signal)
    {
    case 0:
      return GDB_SIGNAL_0;

    case LINUX_SIGHUP:
      return GDB_SIGNAL_HUP;

    case LINUX_SIGINT:
      return GDB_SIGNAL_INT;

    case LINUX_SIGQUIT:
      return GDB_SIGNAL_QUIT;

    case LINUX_SIGILL:
      return GDB_SIGNAL_ILL;

    case LINUX_SIGTRAP:
      return GDB_SIGNAL_TRAP;

    case LINUX_SIGABRT:
      return GDB_SIGNAL_ABRT;

    case LINUX_SIGBUS:
      return GDB_SIGNAL_BUS;

    case LINUX_SIGFPE:
      return GDB_SIGNAL_FPE;

    case LINUX_SIGKILL:
      return GDB_SIGNAL_KILL;

    case LINUX_SIGUSR1:
      return GDB_SIGNAL_USR1;

    case LINUX_SIGSEGV:
      return GDB_SIGNAL_SEGV;

    case LINUX_SIGUSR2:
      return GDB_SIGNAL_USR2;

    case LINUX_SIGPIPE:
      return GDB_SIGNAL_PIPE;

    case LINUX_SIGALRM:
      return GDB_SIGNAL_ALRM;

    case LINUX_SIGTERM:
      return GDB_SIGNAL_TERM;

    case LINUX_SIGCHLD:
      return GDB_SIGNAL_CHLD;

    case LINUX_SIGCONT:
      return GDB_SIGNAL_CONT;

    case LINUX_SIGSTOP:
      return GDB_SIGNAL_STOP;

    case LINUX_SIGTSTP:
      return GDB_SIGNAL_TSTP;

    case LINUX_SIGTTIN:
      return GDB_SIGNAL_TTIN;

    case LINUX_SIGTTOU:
      return GDB_SIGNAL_TTOU;

    case LINUX_SIGURG:
      return GDB_SIGNAL_URG;

    case LINUX_SIGXCPU:
      return GDB_SIGNAL_XCPU;

    case LINUX_SIGXFSZ:
      return GDB_SIGNAL_XFSZ;

    case LINUX_SIGVTALRM:
      return GDB_SIGNAL_VTALRM;

    case LINUX_SIGPROF:
      return GDB_SIGNAL_PROF;

    case LINUX_SIGWINCH:
      return GDB_SIGNAL_WINCH;

    /* No way to differentiate between SIGIO and SIGPOLL.
       Therefore, we just handle the first one.  */
    case LINUX_SIGIO:
      return GDB_SIGNAL_IO;

    case LINUX_SIGPWR:
      return GDB_SIGNAL_PWR;

    case LINUX_SIGSYS:
      return GDB_SIGNAL_SYS;

    /* SIGRTMIN and SIGRTMAX are not continuous in <gdb/signals.def>,
       therefore we have to handle them here.  */
    case LINUX_SIGRTMIN:
      return GDB_SIGNAL_REALTIME_32;

    case LINUX_SIGRTMAX:
      return GDB_SIGNAL_REALTIME_64;
    }

  if (signal >= LINUX_SIGRTMIN + 1 && signal <= LINUX_SIGRTMAX - 1)
    {
      int offset = signal - LINUX_SIGRTMIN + 1;

      return (enum gdb_signal) ((int) GDB_SIGNAL_REALTIME_33 + offset);
    }

  return GDB_SIGNAL_UNKNOWN;
}

/* Implementation of `gdbarch_gdb_signal_to_target', as defined in
   gdbarch.h.  This function is not static because it is exported to
   other -tdep files.  */

int
linux_gdb_signal_to_target (/*struct gdbarch *gdbarch,*/
			    enum gdb_signal signal)
{
  switch (signal)
    {
    case GDB_SIGNAL_0:
      return 0;

    case GDB_SIGNAL_HUP:
      return LINUX_SIGHUP;

    case GDB_SIGNAL_INT:
      return LINUX_SIGINT;

    case GDB_SIGNAL_QUIT:
      return LINUX_SIGQUIT;

    case GDB_SIGNAL_ILL:
      return LINUX_SIGILL;

    case GDB_SIGNAL_TRAP:
      return LINUX_SIGTRAP;

    case GDB_SIGNAL_ABRT:
      return LINUX_SIGABRT;

    case GDB_SIGNAL_FPE:
      return LINUX_SIGFPE;

    case GDB_SIGNAL_KILL:
      return LINUX_SIGKILL;

    case GDB_SIGNAL_BUS:
      return LINUX_SIGBUS;

    case GDB_SIGNAL_SEGV:
      return LINUX_SIGSEGV;

    case GDB_SIGNAL_SYS:
      return LINUX_SIGSYS;

    case GDB_SIGNAL_PIPE:
      return LINUX_SIGPIPE;

    case GDB_SIGNAL_ALRM:
      return LINUX_SIGALRM;

    case GDB_SIGNAL_TERM:
      return LINUX_SIGTERM;

    case GDB_SIGNAL_URG:
      return LINUX_SIGURG;

    case GDB_SIGNAL_STOP:
      return LINUX_SIGSTOP;

    case GDB_SIGNAL_TSTP:
      return LINUX_SIGTSTP;

    case GDB_SIGNAL_CONT:
      return LINUX_SIGCONT;

    case GDB_SIGNAL_CHLD:
      return LINUX_SIGCHLD;

    case GDB_SIGNAL_TTIN:
      return LINUX_SIGTTIN;

    case GDB_SIGNAL_TTOU:
      return LINUX_SIGTTOU;

    case GDB_SIGNAL_IO:
      return LINUX_SIGIO;

    case GDB_SIGNAL_XCPU:
      return LINUX_SIGXCPU;

    case GDB_SIGNAL_XFSZ:
      return LINUX_SIGXFSZ;

    case GDB_SIGNAL_VTALRM:
      return LINUX_SIGVTALRM;

    case GDB_SIGNAL_PROF:
      return LINUX_SIGPROF;

    case GDB_SIGNAL_WINCH:
      return LINUX_SIGWINCH;

    case GDB_SIGNAL_USR1:
      return LINUX_SIGUSR1;

    case GDB_SIGNAL_USR2:
      return LINUX_SIGUSR2;

    case GDB_SIGNAL_PWR:
      return LINUX_SIGPWR;

    case GDB_SIGNAL_POLL:
      return LINUX_SIGPOLL;

    /* GDB_SIGNAL_REALTIME_32 is not continuous in <gdb/signals.def>,
       therefore we have to handle it here.  */
    case GDB_SIGNAL_REALTIME_32:
      return LINUX_SIGRTMIN;

    /* Same comment applies to _64.  */
    case GDB_SIGNAL_REALTIME_64:
      return LINUX_SIGRTMAX;

    default:
      break;
    }

  /* GDB_SIGNAL_REALTIME_33 to _64 are continuous.  */
  if (signal >= GDB_SIGNAL_REALTIME_33
      && signal <= GDB_SIGNAL_REALTIME_63)
    {
      int offset = signal - GDB_SIGNAL_REALTIME_33;

      return LINUX_SIGRTMIN + 1 + offset;
    }

  return -1;
}
