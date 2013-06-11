#ifndef ICONV_H
#define ICONV_H

typedef void *iconv_t;

iconv_t iconv_open(const char *tocode, const char *fromcode);
size_t iconv(iconv_t cd, char **inbuf, size_t *inbytes,
                         char **outbuf, size_t *outbytes);
int iconv_close(iconv_t cd);

#endif
