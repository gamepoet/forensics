#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/errno.h>
#include "backtrace.h"
#include "forensics.h"

static void signal_handler(int sig, siginfo_t* info, void* context) {
  // save the current value of errno in case a function that is called modifies it. This is
  // recommended by the sigaction(2) man page.
  int saved_errno = errno;

  // TODO: this is probably unsafe to do since many functions are not safe to call in a signal handler
  const char* message = NULL;
  switch (sig) {
    case SIGABRT:
      message = "got signal: SIGABRT";
      break;
    case SIGBUS:
      message = "got signal: SIGBUS";
      break;
    case SIGFPE:
      message = "got signal: SIGFPE";
      break;
    case SIGILL:
      message = "got signal: SIGILL";
      break;
    case SIGSEGV:
      message = "got signal: SIGSEGV";
      break;
    default:
      message = "got unexpected signal";
      break;
  }

  forensics_report_crash(message);

  // restore the old errno value
  errno = saved_errno;
}

static void register_handler(int sig) {
  struct sigaction action;
  memset(&action, 0, sizeof(action));
  action.sa_sigaction = &signal_handler;
  action.sa_flags = SA_SIGINFO;
  sigemptyset(&action.sa_mask);
  // TODO: should we block these signals while our signal handler is running?
  // sigaddset(&action.sa_mask, SIGABRT);
  // sigaddset(&action.sa_mask, SIGBUS);
  // sigaddset(&action.sa_mask, SIGFPE);
  // sigaddset(&action.sa_mask, SIGILL);
  // sigaddset(&action.sa_mask, SIGSEGV);

  int result = sigaction(sig, &action, NULL);
  if (result != 0) {
    forensics_report_crash("failed to register signal handlers");
  }
}

static void unregister_handler(int sig) {
  struct sigaction action;
  memset(&action, 0, sizeof(action));
  action.sa_handler = SIG_DFL;
  action.sa_flags = SA_SIGINFO;
  int result = sigaction(sig, &action, NULL);
  if (result != 0) {
    forensics_report_crash("failed to unregister signal handlers");
  }
}

void forensics_private_register_signal_handlers() {
  register_handler(SIGABRT); // abort(3) called
  register_handler(SIGBUS);  // bus error
  register_handler(SIGFPE);  // floating-point exception
  register_handler(SIGILL);  // illegal instruction
  register_handler(SIGSEGV); // segmentation violation
}

void forensics_private_unregister_signal_handlers() {
  unregister_handler(SIGSEGV);
  unregister_handler(SIGILL);
  unregister_handler(SIGFPE);
  unregister_handler(SIGBUS);
  unregister_handler(SIGABRT);
}
