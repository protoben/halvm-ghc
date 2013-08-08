#ifndef MINLIBC_SIGNAL_H
#define MINLIBC_SIGNAL_H

#include <sys/types.h>

typedef signed int    siginfo_t;
typedef unsigned long sigset_t;

int sigemptyset(sigset_t *set);
int sigfillset(sigset_t *set);
int sigaddset(sigset_t *set, int signum);
int sigdelset(sigset_t *set, int signum);
int sigismember(const sigset_t *set, int signum);

int sigprocmask(int how, const sigset_t *set, sigset_t *oldset);

int raise(int sig);
int kill(pid_t pid, int sig);

#endif
