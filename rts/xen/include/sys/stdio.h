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
#include <sys/stat.h>
#include <sys/termios.h>
#include <sys/epoll.h>
#include <iconv.h>

#define EOF       (-1)
#define BUFSIZ    8192

#define S_IFMT     0170000
#define S_IFSOCK   0140000
#define S_IFLNK    0120000
#define S_IFREG    0100000
#define S_IFBLK    0060000
#define S_IFDIR    0040000
#define S_IFCHR    0020000
#define S_IFIFO    0010000
#define S_ISUID    0004000
#define S_ISGID    0002000
#define S_ISVTX    0001000
#define S_IRWXU    00700
#define S_IRUSR    00400
#define S_IWUSR    00200
#define S_IXUSR    00100
#define S_IRWXG    00070
#define S_IRGRP    00040
#define S_IWGRP    00020
#define S_IXGRP    00010
#define S_IRWXO    00007
#define S_IROTH    00004
#define S_IWOTH    00002
#define S_IXOTH    00001

#define S_ISSOCK(x) (((x) & S_IFMT) == S_IFSOCK)
#define S_ISFIFO(x) (((x) & S_IFMT) == S_IFIFO)
#define S_ISDIR(x)  (((x) & S_IFMT) == S_IFDIR)
#define S_ISBLK(x)  (((x) & S_IFMT) == S_IFBLK)
#define S_ISCHR(x)  (((x) & S_IFMT) == S_IFCHR)
#define S_ISREG(x)  (((x) & S_IFMT) == S_IFREG)

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
typedef unsigned long long eventfd_t;
struct utimbuf {};
typedef struct {} fd_set;
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
int utime(const char *, const struct utimbuf *);
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
int open(const char *pathname, int flags, ...);
int kill(pid_t pid, int sig);
int eventfd_write(int fd, eventfd_t value);
int eventfd(unsigned int initval, int flags);
int epoll_create(int size);
int epoll_ctl(int epfd, int op, int fd, struct epoll_event *event);
int epoll_wait(int, struct epoll_event *, int, int);
int select(int nfds, fd_set *reads, fd_set *writes, fd_set *excs,
           struct timeval *timeout);
void FD_ZERO(fd_set *set);
void FD_SET(int fd, fd_set *set);
int __xstat(int ver, const char *path, struct stat *stat_buf);
int __lxstat(int ver, const char *path, struct stat *stat_buf);
int __fxstat(int ver, int fildes, struct stat *stat_buf);
int fstat(int fd, struct stat *buf);
int lstat(const char *path, struct stat *buf);
char *nl_langinfo(nl_item item);

#endif
