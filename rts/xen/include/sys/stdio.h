// BANNERSTART
// - Copyright 2006-2008, Galois, Inc.
// - This software is distributed under a standard, three-clause BSD license.
// - Please see the file LICENSE, distributed with this software, for specific
// - terms and conditions.
// Author: Adam Wick <awick@galois.com>
// BANNEREND
#ifndef XEN_HOST_STDIO_H
#define XEN_HOST_STDIO_H

// libgmp checks for this to determine if it should be using FILE
// and when it does not, things go bad.
#ifndef H_STDIO
#define H_STDIO
#endif


#include <stdarg.h>
#include <types.h>
#include <time.h>
#include <stat.h>

#define EOF (-1)

typedef unsigned long FILE;

#define _p(_x) ((void *)(unsigned long)(_x))
int printf(const char *fmt, ...);
int fprintf(FILE *stream, const char *format, ...);
int vsnprintf(char *buf, size_t size, const char *fmt, va_list args);
int snprintf(char *buf, size_t size, const char *fmt, ...);
int sprintf(char * buf, const char *fmt, ...);
int vfprintf(FILE *stream, const char *format, va_list ap);

int putchar(int c);
int puts(const char *s);
int fputs(const char *s, FILE *stream);
int fputc(int c, FILE *stream);
size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream);

int fflush(FILE *stream);
FILE *fopen(const char *path, const char *mode);
int fclose(FILE *fp);

size_t fread(void *, size_t, size_t, FILE *);
int feof(FILE *);
long ftell(FILE *);
int fseek(FILE *, long, int);
int getc(FILE *stream);

#define SEEK_SET 0x1
#define SEEK_CUR 0x2
#define SEEK_END 0x3

void perror(const char *s);

extern FILE *stdout;
extern FILE *stdin;
extern FILE *stderr;

typedef int sigset_t;
typedef int ssize_t;
typedef unsigned long int nfds_t;
typedef unsigned long long eventfd_t;
struct termios {};
struct utimbuf {};
struct pollfd {};
struct epoll_event {};
typedef struct {} fd_set;
typedef void *iconv_t;
typedef int nl_item;

int chmod(const char *path, mode_t mode);
int creat(const char *path, mode_t mode);
int dup(int fildes);
int dup2(int fildes, int fildes2);
int isatty(int fd);
mode_t umask(mode_t cmask);
pid_t getpid(void);
pid_t fork(void);
int link(const char *path1, const char *path2);
int pipe(int fildes[2]);
pid_t waitpid(pid_t pid, int *stat_loc, int options);
int utime(const char *path, const struct utimbuf *times);
int tcsetattr(int fd, int optional_actions, const struct termios *termios_p);
int tcgetattr(int fd, struct termios *termios_p);
int sigprocmask(int how, const sigset_t *set, sigset_t *oldset);
int sigaddset(sigset_t *set, int signum);
int sigemptyset(sigset_t *set);
int mkfifo(const char *pathname, mode_t mode);
ssize_t write(int filedes, const void *buf, size_t nbyte);
ssize_t read(int fildes, void *buf, size_t nbyte);
off_t lseek(int fildes, off_t offset, int whence);
int mkdir(const char *path, mode_t mode);
uid_t getuid(void);
uid_t geteuid(void);
gid_t getgid(void);
gid_t getegid(void);
int open(const char *pathname, int flags);
int kill(pid_t pid, int sig);
int poll(struct pollfd fds[], nfds_t nfds, int timeout);
int eventfd_write(int fd, eventfd_t value);
int eventfd(unsigned int initval, int flags);
int epoll_create(int size);
int epoll_ctl(int epfd, int op, int fd, struct epoll_event *event);
int epoll_wait(int, struct epoll_event *, int, int);
int select(int nfds, fd_set *reads, fd_set *writes, fd_set *excs,
           struct timeval *timeout);
iconv_t iconv_open(const char *tocode, const char *fromcode);
size_t iconv(iconv_t cd, char **inbuf, size_t *inbytes,
                         char **outbuf, size_t *outbytes);
int iconv_close(iconv_t cd);
int __xstat(int ver, const char *path, struct stat *stat_buf);
int __lxstat(int ver, const char *path, struct stat *stat_buf);
int __fxstat(int ver, int fildes, struct stat *stat_buf);
char *nl_langinfo(nl_item item);

#endif
