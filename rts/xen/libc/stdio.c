// BANNERSTART
// - Copyright 2006-2008, Galois, Inc.
// - This software is distributed under a standard, three-clause BSD license.
// - Please see the file LICENSE, distributed with this software, for specific
// - terms and conditions.
// Author: Adam Wick <awick@galois.com>
// BANNEREND
#include <stdio.h>
#include <econsole.h>
#include <string.h>
#include <errno.h>
#include <hypercall.h>
#include <unistd.h>
#include <poll.h>

FILE *stdout = (FILE*)0x0badbead;
FILE *stdin = (FILE*)0xdeadbead;
FILE *stderr = (FILE*)0xeebadbad;

void abort(void);

#define isdigit(c) ((c) >= '0' && (c) <= '9')
#define isxdigit(c) (isdigit(c) || \
    (((c) >= 'a') && ((c) <= 'f')) || \
    (((c) >= 'A') && ((c) <= 'F')))
#define islower(c) (((c) >= 'a') && ((c) <= 'z'))
#define toupper(c) (islower(c) ? ((c) - ('a' - 'A')) : (c))

static int skip_atoi(const char **s)
{
  int i=0;

  while (isdigit(**s))
    i = i*10 + *((*s)++) - '0';
  return i;
}

#define ZEROPAD 1               /* pad with zero */
#define SIGN    2               /* unsigned/signed long */
#define PLUS    4               /* show plus */
#define SPACE   8               /* space if plus */
#define LEFT    16              /* left justified */
#define SPECIAL 32              /* 0x */
#define LARGE   64              /* use 'ABCDEF' instead of 'abcdef' */

static char * number(char * buf, char * end, long long num, int base, int size, int precision, int type)
{
  char c,sign,tmp[66];
  const char *digits;
  const char small_digits[] = "0123456789abcdefghijklmnopqrstuvwxyz";
  const char large_digits[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  int i;

  digits = (type & LARGE) ? large_digits : small_digits;
  if (type & LEFT)
    type &= ~ZEROPAD;
  if (base < 2 || base > 36)
    return buf;
  c = (type & ZEROPAD) ? '0' : ' ';
  sign = 0;
  if (type & SIGN) {
    if (num < 0) {
      sign = '-';
      num = -num;
      size--;
    } else if (type & PLUS) {
      sign = '+';
      size--;
    } else if (type & SPACE) {
      sign = ' ';
      size--;
    }
  }
  if (type & SPECIAL) {
    if (base == 16)
      size -= 2;
    else if (base == 8)
      size--;
  }
  i = 0;
  if (num == 0)
    tmp[i++]='0';
  else 
  {
    /* XXX KAF: force unsigned mod and div. */
    unsigned long long num2=(unsigned long long)num;
    unsigned int base2=(unsigned int)base;
    while (num2 != 0) { tmp[i++] = digits[num2%base2]; num2 /= base2; }
  }
  if (i > precision)
    precision = i;
  size -= precision;
  if (!(type&(ZEROPAD+LEFT))) {
    while(size-->0) {
      if (buf <= end)
        *buf = ' ';
      ++buf;
    }
  }
  if (sign) {
    if (buf <= end)
      *buf = sign;
    ++buf;
  }
  if (type & SPECIAL) {
    if (base==8) {
      if (buf <= end)
        *buf = '0';
      ++buf;
    } else if (base==16) {
      if (buf <= end)
        *buf = '0';
      ++buf;
      if (buf <= end)
        *buf = digits[33];
      ++buf;
    }
  }
  if (!(type & LEFT)) {
    while (size-- > 0) {
      if (buf <= end)
        *buf = c;
      ++buf;
    }
  }
  while (i < precision--) {
    if (buf <= end)
      *buf = '0';
    ++buf;
  }
  while (i-- > 0) {
    if (buf <= end)
      *buf = tmp[i];
    ++buf;
  }
  while (size-- > 0) {
    if (buf <= end)
      *buf = ' ';
    ++buf;
  }
  return buf;
}

int __fprintf_chk(FILE * stream, int flag __attribute__ ((unused)),
    const char * format, ...)
{
  va_list args;
  int res;

  va_start(args, format);
  res = vfprintf(stream, format, args);
  va_end(args);
  return res;
}

int printf(const char *format, ...)
{
  va_list args;
  int res;

  va_start(args, format);
  res = vfprintf(stdout, format, args);
  va_end(args);
  return res;
}

int fprintf(FILE *stream, const char *format, ...)
{
  va_list args;
  int res;

  va_start(args, format);
  res = vfprintf(stream, format, args);
  va_end(args);
  return res;
}

int vsnprintf(char *buf, size_t size, const char *fmt, va_list args)
{
  // Written by Rolf 
  int len;
  unsigned long long num;
  int i, base;
  char *str, *end, c;
  const char *s;

  int flags;          /* flags to number() */

  int field_width;    /* width of output field */
  int precision;              /* min. # of digits for integers; max
                                 number of chars for from string */
  int qualifier;              /* 'h', 'l', or 'L' for integer fields */
  /* 'z' support added 23/7/1999 S.H.    */
  /* 'z' changed to 'Z' --davidm 1/25/99 */

  str = buf;
  end = buf + size - 1;

  if (end < buf - 1) {
    end = ((void *) -1);
    size = end - buf + 1;
  }

  for (; *fmt ; ++fmt) {
    if (*fmt != '%') {
      if (str <= end)
        *str = *fmt;
      ++str;
      continue;
    }

    /* process flags */
    flags = 0;
repeat:
    ++fmt;          /* this also skips first '%' */
    switch (*fmt) {
      case '-': flags |= LEFT; goto repeat;
      case '+': flags |= PLUS; goto repeat;
      case ' ': flags |= SPACE; goto repeat;
      case '#': flags |= SPECIAL; goto repeat;
      case '0': flags |= ZEROPAD; goto repeat;
    }

    /* get field width */
    field_width = -1;
    if (isdigit(*fmt))
      field_width = skip_atoi(&fmt);
    else if (*fmt == '*') {
      ++fmt;
      /* it's the next argument */
      field_width = va_arg(args, int);
      if (field_width < 0) {
        field_width = -field_width;
        flags |= LEFT;
      }
    }

    /* get the precision */
    precision = -1;
    if (*fmt == '.') {
      ++fmt;
      if (isdigit(*fmt))
        precision = skip_atoi(&fmt);
      else if (*fmt == '*') {
        ++fmt;
        /* it's the next argument */
        precision = va_arg(args, int);
      }
      if (precision < 0)
        precision = 0;
    }

    /* get the conversion qualifier */
    qualifier = -1;
    if (*fmt == 'h' || *fmt == 'l' || *fmt == 'L' || *fmt =='Z') {
      qualifier = *fmt;
      ++fmt;
      if (qualifier == 'l' && *fmt == 'l') {
        qualifier = 'L';
        ++fmt;
      }
    }
    if (*fmt == 'q') {
      qualifier = 'L';
      ++fmt;
    }

    /* default base */
    base = 10;

    switch (*fmt) {
      case 'c':
        if (!(flags & LEFT)) {
          while (--field_width > 0) {
            if (str <= end)
              *str = ' ';
            ++str;
          }
        }
        c = (unsigned char) va_arg(args, int);
        if (str <= end)
          *str = c;
        ++str;
        while (--field_width > 0) {
          if (str <= end)
            *str = ' ';
          ++str;
        }
        continue;

      case 's':
        s = va_arg(args, char *);
        if (!s)
          s = "<NULL>";

        len = strnlen(s, precision);

        if (!(flags & LEFT)) {
          while (len < field_width--) {
            if (str <= end)
              *str = ' ';
            ++str;
          }
        }
        for (i = 0; i < len; ++i) {
          if (str <= end)
            *str = *s;
          ++str; ++s;
        }
        while (len < field_width--) {
          if (str <= end)
            *str = ' ';
          ++str;
        }
        continue;

      case 'p':
        if (field_width == -1) {
          field_width = 2*sizeof(void *);
          flags |= ZEROPAD;
        }
        str = number(str, end,
            (unsigned long) va_arg(args, void *),
            16, field_width, precision, flags);
        continue;

      case 'n':
        /* FIXME:
         * What does C99 say about the overflow case here? */
        if (qualifier == 'l') {
          long * ip = va_arg(args, long *);
          *ip = (str - buf);
        } else if (qualifier == 'Z') {
          size_t * ip = va_arg(args, size_t *);
          *ip = (str - buf);
        } else {
          int * ip = va_arg(args, int *);
          *ip = (str - buf);
        }
        continue;

      case '%':
        if (str <= end)
          *str = '%';
        ++str;
        continue;

      case 'o':
        base = 8;
        break;

      case 'X':
        flags |= LARGE;
      case 'x':
        base = 16;
        break;

      case 'd':
      case 'i':
        flags |= SIGN;
      case 'u':
        break;

      default:
        if (str <= end)
          *str = '%';
        ++str;
        if (*fmt) {
          if (str <= end)
            *str = *fmt;
          ++str;
        } else {
          --fmt;
        }
        continue;
    }
    if (qualifier == 'L')
      num = va_arg(args, long long);
    else if (qualifier == 'l') {
      num = va_arg(args, unsigned long);
      if (flags & SIGN)
        num = (signed long) num;
    } else if (qualifier == 'Z') {
      num = va_arg(args, size_t);
    } else if (qualifier == 'h') {
      num = (unsigned short) va_arg(args, int);
      if (flags & SIGN)
        num = (signed short) num;
    } else {
      num = va_arg(args, unsigned int);
      if (flags & SIGN)
        num = (signed int) num;
    }

    str = number(str, end, num, base,
        field_width, precision, flags);
  }
  if (str <= end)
    *str = '\0';
  else if (size > 0)
    /* don't write out a null byte if the buf size is zero */
    *end = '\0';
  /* the trailing null byte doesn't count towards the total
   * ++str;
   */
  return str-buf;
}

int sprintf(char * buf, const char *fmt, ...)
{
  va_list args;
  int i;

  va_start(args, fmt);
  i = vsnprintf(buf, 0xFFFFFFFFUL, fmt, args);
  va_end(args);
  return i;
}

int snprintf(char *buf, size_t size, const char *fmt, ...)
{
  va_list args;
  int i;

  va_start(args, fmt);
  i = vsnprintf(buf, size, fmt, args);
  va_end(args);
  return i;
}

int vfprintf(FILE *stream, const char *format, va_list ap)
{
  static char buf[4096];

  if((stream == stdin) || (stream == stdout) || (stream == stderr)) {
    int r = vsnprintf(buf, sizeof(buf), format, ap);
    emergency_console_msg(r, buf);
    return r;
  } else {
    return -1;
  }
}

int putchar(int c) {
  emergency_console_msg(1, (char*)&c);
  return c;
}

int puts(const char *s)
{
  int len = strlen(s);
  emergency_console_msg(len, (char*)s);
  emergency_console_msg(1,"\n");
  return 0;
}

int fputs(const char *s, FILE *stream)
{
  if((stream == stdin) || (stream == stdout) || (stream == stderr)) {
    return puts(s);
  } else {
    errno = EBADF;
    return EOF;
  }
}

int fputc(int c, FILE *stream)
{
  if(fprintf(stream, "%c", c) >= 1)
    return (int)c;
  else
    return EOF;
}

size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream)
{
  size_t size_in_chars = size * nmemb, i;

  for(i = 0; i < size_in_chars; i++)
    if(fputc(*(char*)((unsigned long)ptr + i), stream) == EOF)
      return i / size;

  return nmemb;
}

int fflush(FILE *stream)
{
  if((stream == stdin) || (stream == stdout) || (stream == stderr)) {
    return 0;
  } else {
    errno = EBADF;
    return EOF;
  }
}

FILE *fopen(const char *path __attribute__((unused)),
    const char *mode __attribute__((unused)))
{
  printf("fopen\n");
  errno = EACCES;
  return 0;
}

size_t fread(void *ptr    __attribute__((unused)),
    size_t size  __attribute__((unused)),
    size_t nmemb __attribute__((unused)),
    FILE *stream __attribute__((unused)))
{
  // XXX is this the right errno value?
  printf("fread\n");
  errno = EACCES;
  return 0;
}

int feof(FILE *stream __attribute__((unused)))
{
  printf("feof\n");
  errno = EBADF;
  return -1;
}

long ftell(FILE *stream __attribute__((unused)))
{
  printf("ftell\n");
  errno = EBADF;
  return -1;
}

int fseek(FILE *stream __attribute__((unused)),
    long offset  __attribute__((unused)),
    int whence   __attribute__((unused)))
{
  printf("fseek\n");
  errno = EBADF;
  return 0;
}

int getc(FILE *stream __attribute__((unused)))
{
  printf("getc\n");
  errno = EBADF;
  return -1;
}

int fclose(FILE *fp __attribute__((unused)))
{
  printf("fclose\n");
  errno = EBADF;
  return EOF;
}

void perror(const char *s)
{
  printf("%s: %s\n", s, strerror(errno));
}

int unlink(const char *pathname __attribute__ ((unused)))
{
  printf("unlink\n");
  errno = ENOENT;
  return (-1);
}

int access(const char *pathname __attribute__ ((unused)),
    int mode __attribute__ ((unused)))
{
  printf("access\n");
  errno = ENOENT;
  return (-1);
}

int ftruncate(int fd __attribute__ ((unused)),
    off_t length __attribute__ ((unused)))
{
  printf("ftruncate\n");
  errno = EPERM;
  return (-1);
}

int statfs(const char *path __attribute__ ((unused)),
    struct statfs *buf __attribute__ ((unused)))
{
  printf("statfs\n");
  errno = ENOSYS;
  return (-1);
}

int close(int fd __attribute__ ((unused)))
{
  printf("close\n");
  errno = EBADF;
  return (-1);
}

size_t __getdelim(char **lineptr __attribute__ ((unused)),
    size_t *n __attribute__ ((unused)),
    int delim __attribute__ ((unused)),
    FILE *stream __attribute__ ((unused)))
{
  printf("__getdelim\n");
  errno = ENOSYS;
  return (-1);
}

size_t getline(char **lineptr __attribute__((unused)),
    size_t *n __attribute__ ((unused)),
    FILE *stream __attribute__ ((unused)))
{
  printf("getline\n");
  errno = ENOSYS;
  return (-1);
}

int chmod(const char *path __attribute__((unused)),
    mode_t mode __attribute__((unused)))
{
  printf("chmod\n");
  errno = ENOSYS;
  return (-1);
}

int creat(const char *path __attribute__((unused)),
    mode_t mode  __attribute__((unused)))
{
  printf("creat\n");
  errno = ENOSYS;
  return (-1);
}

int dup(int fildes __attribute__((unused)))
{
  printf("dup\n");
  errno = ENOSYS;
  return (-1);
}

int dup2(int fildes __attribute__((unused)),
    int fildes2 __attribute__((unused)))
{
  printf("dup2\n");
  errno = ENOSYS;
  return (-1);
}

int isatty(int fd)
{
  if(fd >= 0 && fd <= 2)
    return 1;
  errno = EBADF;
  return 0;
}

mode_t umask(mode_t cmask)
{
  static mode_t mask = 0;
  int retval = mask;
  printf("umask\n");
  mask = cmask;
  return retval;
}

pid_t getpid(void)
{
  printf("getpid\n");
  return 0xca5cad1a;
}

pid_t fork(void)
{
  printf("fork\n");
  errno = EAGAIN;
  return -1;
}

int link(const char *path1 __attribute__((unused)),
    const char *path2 __attribute__((unused)))
{
  printf("link\n");
  errno = ENOENT;
  return -1;
}

int pipe(int fildes[2] __attribute__((unused)))
{
  printf("pipe\n");
  errno = EMFILE;
  return -1;
}

pid_t waitpid(pid_t pid __attribute__((unused)),
    int *stat_loc __attribute__((unused)),
    int options __attribute__((unused)))
{
  printf("waitpid\n");
  errno = ECHILD;
  return -1;
}

int utime(const char *path __attribute__((unused)),
    const struct utimbuf *times __attribute__((unused)))
{
  printf("utime\n");
  errno = ENOENT;
  return -1;
}

int tcsetattr(int fd __attribute__((unused)),
    int optional_actions __attribute__((unused)),
    const struct termios *termios_p __attribute__((unused)))
{
  printf("tcsetattr\n");
  errno = ENOSYS;
  return -1;
}

int tcgetattr(int fd __attribute__((unused)),
    struct termios *termios_p __attribute__((unused)))
{
  printf("tcgetattr\n");
  errno = ENOSYS;
  return -1;
}

int sigprocmask(int how __attribute__((unused)),
    const sigset_t *set __attribute__((unused)),
    sigset_t *oldset __attribute__((unused)))
{
  printf("sigprocmask\n");
  errno = EINVAL;
  return -1;
}

int sigaddset(sigset_t *set __attribute__ ((unused)),
    int signum __attribute__ ((unused)))
{
  printf("sigaddset\n");
  errno = EINVAL;
  return -1;
}

int sigemptyset(sigset_t *set __attribute__ ((unused)))
{
  printf("sigemptyset\n");
  errno = EINVAL;
  return -1;
}

int mkfifo(const char *pathname __attribute__ ((unused)),
    mode_t mode __attribute__ ((unused)))
{
  printf("mkfifo\n");
  errno = ENOENT;
  return -1;
}

ssize_t write(int filedes, const void *buf, size_t nbyte)
{
  printf("write\n");
  if(filedes == 0 || filedes > 2) {
    errno = EBADF;
    return -1;
  }
  emergency_console_msg(nbyte, (char*)buf);
  return nbyte;
}

ssize_t read(int fildes, void *buf, size_t nbyte)
{
  printf("read\n");
  if(fildes != 0) {
    errno = EBADF;
    return -1;
  }

  return emergency_console_read(buf, nbyte);
}

off_t lseek(int fildes __attribute__ ((unused)),
    off_t offset __attribute__ ((unused)),
    int whence __attribute__ ((unused)))
{
  printf("lseek\n");
  errno = EBADF;
  return -1;
}


int mkdir(const char *path __attribute__((unused)),
    mode_t mode __attribute__((unused)))
{
  printf("mkdir\n");
  errno = ENOENT;
  return -1;
}

/* HaLVM users are affable oddballs? */
uid_t getuid(void)
{
  printf("getuid\n");
  return 0x0ddba11;
}

uid_t geteuid(void)
{
  printf("geteuid\n");
  return 0x0ddba11;
}

gid_t getgid(void)
{
  printf("getgid\n");
  return 0xaffab1e;
}

gid_t getegid(void)
{
  printf("getegid\n");
  return 0xaffab1e;
}

int open(const char *pathname __attribute__((unused)),
    int flags __attribute__((unused)),
    ...)
{
  printf("open\n");
  errno = EACCES;
  return -1;
}

int kill(pid_t pid __attribute__((unused)),
    int sig __attribute__((unused)))
{
  printf("kill\n");
  errno = EPERM;
  return -1;
}

int poll(struct pollfd *fds __attribute__((unused)),
    nfds_t nfds,
         int timeout)
{
  printf("poll called with %ld fds and a timeout of %d\n", nfds, timeout);
  switch(timeout) {
    case -1:
      printf("  ... which will never wake up, so I'm giving up.\n");
      abort();
    case 0:
      return 0;
    default:
      block_domain(timeout);
      return 0;
  }
}

int eventfd_write(int fd __attribute__((unused)),
                  eventfd_t value __attribute__((unused)))
{
  printf("eventfd_write\n");
  errno = EINVAL;
  return -1;
}

int eventfd(unsigned int initval __attribute__((unused)),
            int flags __attribute__((unused)))
{
  printf("eventfd\n");
  errno = EINVAL;
  return -1;
}

int epoll_create(int size __attribute__((unused)))
{
  printf("epoll_create\n");
  errno = ENOMEM;
  return -1;
}

int epoll_ctl(int epfd __attribute__((unused)),
              int op __attribute__((unused)),
              int fd __attribute__((unused)),
              struct epoll_event *event __attribute__((unused)))
{
  printf("epoll_ctl\n");
  errno = EINVAL;
  return -1;
}

int epoll_wait(int epfd __attribute__((unused)),
               struct epoll_event *events __attribute__((unused)),
               int maxevents __attribute__((unused)),
               int timeout)
{
  printf("epoll_wait\n");
  switch(timeout) {
    case -1:
      printf("epoll_wait with endless wait. aborting.\n");
      abort();
    case 0:
      return 0;
    default:
      block_domain(timeout);
      return 0;
  }
}

void FD_ZERO(fd_set *set __attribute__((unused)))
{
}

void FD_SET(int fd __attribute__((unused)),
            fd_set *set __attribute__((unused)))
{
}

int select(int nfds __attribute__((unused)),
           fd_set *reads __attribute__((unused)),
           fd_set *writes __attribute__((unused)),
           fd_set *excs __attribute__((unused)),
           struct timeval *timeout)
{
  printf("select\n");
  if(!timeout) {
    printf("select() called with endless wait. aborting.\n");
    abort();
  }

  block_domain((timeout->tv_sec * 1000) + (timeout->tv_usec / 1000));
  return 0;
}

/* GHC apparantly can't get along without iconv. So this is the world's */
/* most unimpressive implementation of it. There is only one iconv_t    */
/* return value (0xacce55ed), and it always translates things exactly   */
/* byte for byte, no matter what you do.                                */
iconv_t iconv_open(const char *tocode __attribute__((unused)),
                   const char *fromcode __attribute__((unused)))
{
  return (iconv_t)0xacce55ed;
}

size_t iconv(iconv_t cd __attribute__((unused)),
             char **inbuf, size_t *inbytesleft,
             char **outbuf, size_t *outbytesleft)
{
  /* The main case is when inbuf is not NULL and *inbuf is not NULL */
  if(inbuf && *inbuf) {
    size_t bytesConverted = 0;

    if(!outbuf || !(*outbuf)) {
      /* this case is not noted by the man page, which is sad */
      printf("bad iconv() case; (*)inbuf is good but (*)outbuf isn't\n");
      errno = EINVAL;
      return -1;
    }

    do {
      if(*inbytesleft == 0)
        return bytesConverted;
      if(*outbytesleft == 0) {
        errno = E2BIG;
        return -1;
      }

      **outbuf       = **inbuf;
      *outbuf       += 1;
      *inbuf        += 1;
      *outbytesleft -= 1;
      *inbytesleft  -= 1;
    } while(1);
  }

  /* the other two cases appear to not apply, or the appropriate return */
  /* value is zero in any case.                                         */
  return 0;
}

int iconv_close(iconv_t cd __attribute__((unused)))
{
  return 0;
}

int fstat(int fd __attribute__((unused)),
          struct stat *buf __attribute__((unused)))
{
  errno = EBADF;
  return -1;
}

int lstat(const char *path __attribute__((unused)),
          struct stat *buf __attribute__((unused)))
{
  errno = ENOENT;
  return -1;
}

int __xstat(int ver __attribute__((unused)),
            const char *path __attribute__((unused)),
            struct stat *stat_buf __attribute__((unused)))
{
  printf("__xstat\n");
  errno = ENOENT;
  return -1;
}

int __lxstat(int ver __attribute__((unused)),
             const char *path __attribute__((unused)),
             struct stat *stat_buf __attribute__((unused)))
{
  printf("__lxstat\n");
  errno = ENOENT;
  return -1;
}

int __fxstat(int ver __attribute__((unused)),
             int fildes __attribute__((unused)),
             struct stat *stat_buf __attribute__((unused)))
{
  printf("__fxstat\n");
  errno = ENOENT;
  return -1;
}

char *nl_langinfo(nl_item item __attribute__((unused)))
{
  return "UTF8";
}
