#ifndef HALVM_TERMIOS_H
#define HALVM_TERMIOS_H

#define NCCS 32

typedef unsigned int  tcflag_t;
typedef unsigned char cc_t;

struct termios {
  tcflag_t c_iflag;
  tcflag_t c_oflag;
  tcflag_t c_cflag;
  tcflag_t c_lflag;
  cc_t     c_line;
  cc_t     c_cc[NCCS];
};

#endif
