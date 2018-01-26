#ifdef URANDOM

#include <errno.h>
#include <locks.h>
#include <Random.h>
#include <runtime_reqs.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static struct crng_state {
  uint32_t state[16];
  time_t init_time; // equal to 0 when uninitialized
  int consumers;
  halvm_mutex_t lock;
} crng = {
  .state = {0},
  .init_time = 0,
  .consumers = 0,
  .lock = 0
};

static void crng_initialize(void);
static ssize_t extract_crng(void *buf, size_t nbytes);

void urandom_init(void)
{
  int err;
  struct timeval t;

  crng_initialize();

  err = gettimeofday(&t, NULL);
  crng.init_time = err > 0 ? 1 : t.tv_sec;
}

int urandom_open(void)
{
  if(crng.init_time == 0) {
    errno = ENODEV;
    return -1;
  }

  ++crng.consumers;
  return URANDOM_FD;
}

int urandom_stat(struct stat *buf, int check_consumers)
{
  if(check_consumers && !crng.consumers) {
    errno = EBADF;
    return -1;
  }

  buf->st_dev     = 6;
  buf->st_ino     = 1033;
  buf->st_mode    = 8630;
  buf->st_nlink   = 1;
  buf->st_uid     = 0;
  buf->st_gid     = 0;
  buf->st_rdev    = 265;
  buf->st_size    = 0;
  buf->st_blksize = 4096;
  buf->st_blocks  = 0;
  buf->st_atime   = crng.init_time;
  buf->st_mtime   = crng.init_time;
  buf->st_ctime   = crng.init_time;

  return 0;
}

ssize_t urandom_read(uint8_t *buf, size_t len)
{
  if(crng.init_time == 0) {
    errno = ENOTSUP;
    return -1;
  }

  if(!crng.consumers) {
    errno = EBADF;
    return -1;
  }

  return extract_crng(buf, len);
}

int urandom_close(void)
{
  if(!crng.consumers) {
    errno = EBADF;
    return -1;
  }

  --crng.consumers;
  return 0;
}

/*
 * ChaCha20 256-bit cipher algorithm, RFC7539
 *
 * Taken from Linux kernel version 4.14.13
 * For reference, see the following:
 * https://github.com/torvalds/linux/blob/master/drivers/char/random.c
 * https://github.com/torvalds/linux/blob/master/lib/chacha20.c
 */

#define round_up(_x,_y) (((_x)-1) | (_y))
#define min(_x,_y) ((_x) < (_y) ? (_x) : (_y))

#define ARRAY_SIZE(_x) (sizeof(_x)/sizeof(*(_x)))

#define CHACHA20_IV_SIZE    16
#define CHACHA20_KEY_SIZE   32
#define CHACHA20_BLOCK_SIZE 64

static inline uint32_t rotl32(uint32_t v, uint8_t n)
{
    return (v << n) | (v >> (sizeof(v) * 8 - n));
}

/*
 * This is the main generator. The state parameter is the state from
 * `struct crng`. The stream parameter is a buffer to store CHACHA20_BLOCK_SIZE
 * bytes of pseudorandomness. This function generates pseudorandomness and
 * mutates the state at the same time.
 */
static inline void chacha20_block(uint32_t *state, void *stream)
{
  uint32_t x[16], *out = stream;
  unsigned i;

  for (i = 0; i < ARRAY_SIZE(x); i++)
    x[i] = state[i];

  for (i = 0; i < 20; i += 2) {
    x[0]  += x[4];    x[12] = rotl32(x[12] ^ x[0],  16);
    x[1]  += x[5];    x[13] = rotl32(x[13] ^ x[1],  16);
    x[2]  += x[6];    x[14] = rotl32(x[14] ^ x[2],  16);
    x[3]  += x[7];    x[15] = rotl32(x[15] ^ x[3],  16);

    x[8]  += x[12];   x[4]  = rotl32(x[4]  ^ x[8],  12);
    x[9]  += x[13];   x[5]  = rotl32(x[5]  ^ x[9],  12);
    x[10] += x[14];   x[6]  = rotl32(x[6]  ^ x[10], 12);
    x[11] += x[15];   x[7]  = rotl32(x[7]  ^ x[11], 12);

    x[0]  += x[4];    x[12] = rotl32(x[12] ^ x[0],   8);
    x[1]  += x[5];    x[13] = rotl32(x[13] ^ x[1],   8);
    x[2]  += x[6];    x[14] = rotl32(x[14] ^ x[2],   8);
    x[3]  += x[7];    x[15] = rotl32(x[15] ^ x[3],   8);

    x[8]  += x[12];   x[4]  = rotl32(x[4]  ^ x[8],   7);
    x[9]  += x[13];   x[5]  = rotl32(x[5]  ^ x[9],   7);
    x[10] += x[14];   x[6]  = rotl32(x[6]  ^ x[10],  7);
    x[11] += x[15];   x[7]  = rotl32(x[7]  ^ x[11],  7);

    x[0]  += x[5];    x[15] = rotl32(x[15] ^ x[0],  16);
    x[1]  += x[6];    x[12] = rotl32(x[12] ^ x[1],  16);
    x[2]  += x[7];    x[13] = rotl32(x[13] ^ x[2],  16);
    x[3]  += x[4];    x[14] = rotl32(x[14] ^ x[3],  16);

    x[10] += x[15];   x[5]  = rotl32(x[5]  ^ x[10], 12);
    x[11] += x[12];   x[6]  = rotl32(x[6]  ^ x[11], 12);
    x[8]  += x[13];   x[7]  = rotl32(x[7]  ^ x[8],  12);
    x[9]  += x[14];   x[4]  = rotl32(x[4]  ^ x[9],  12);

    x[0]  += x[5];    x[15] = rotl32(x[15] ^ x[0],   8);
    x[1]  += x[6];    x[12] = rotl32(x[12] ^ x[1],   8);
    x[2]  += x[7];    x[13] = rotl32(x[13] ^ x[2],   8);
    x[3]  += x[4];    x[14] = rotl32(x[14] ^ x[3],   8);

    x[10] += x[15];   x[5]  = rotl32(x[5]  ^ x[10],  7);
    x[11] += x[12];   x[6]  = rotl32(x[6]  ^ x[11],  7);
    x[8]  += x[13];   x[7]  = rotl32(x[7]  ^ x[8],   7);
    x[9]  += x[14];   x[4]  = rotl32(x[4]  ^ x[9],   7);
  }

  for (i = 0; i < ARRAY_SIZE(x); i++)
    out[i] = x[i] + state[i];

  state[12]++;
}

/*
 * Read the timestamp counter and return the falue. This is included with file scope
 * for inlinability.
 */
static inline uint64_t rdtscll(void)
{
  uint32_t highbits, lowbits;
  uint64_t retval;

  asm volatile("rdtsc" : "=a"(lowbits), "=d"(highbits));
  retval = (((uint64_t)highbits) << 32) | ((uint64_t)lowbits);
  return retval;
}

/*
 * On x86_64, the Linux kernel gets its entropy for the initial state, etc.,
 * from RDRAND if it's available, falling back on the low-order bits of the TSC
 * otherwise. We could do similarly if we had a good way to test for RDRAND.
 * For now, we use the fallback method.
 */
static inline uint64_t random_get_entropy(void)
{
  // Conditional use of RDRAND would go here

  return rdtscll();
}

/*
 * Initialize the CRNG state with a fixed key, some uninitialized randomness
 * (identical for every instance), and some hardware entropy if we have it.
 */
static void crng_initialize(void)
{
  int i;
  uint64_t rv;

  // Start with a key and some unseeded (i.e., 0-seeded) randomness
  memcpy(&crng.state[0], "expand 32-byte k", 16);
  extract_crng(&crng.state[4], sizeof(uint32_t) * 12);

  // Add some entropy to the initial state
  for (i = 4; i < 16; i++) {
    rv = random_get_entropy();
    crng.state[i] ^= rv;
  }
}

/*
 * Extract a block of size CHACHA20_BLOCK_SIZE from the CRNG in a thread-safe
 * way.
 *
 * NOTE: The Linux-kernel implementation periodically reseeds the CRNG from the
 * /dev/random entropy pool and a hardware source, if available. We have neither
 * of these, but we could implement their fallback method, which uses low-order
 * bits from the TSC. See crng_reseed() from crypto/random.c.
 */
static void _extract_crng(uint8_t out[CHACHA20_BLOCK_SIZE])
{
  // Periodic reseeding would go here.

  halvm_acquire_lock(&crng.lock);
  crng.state[14] ^= random_get_entropy();
  chacha20_block(&crng.state[0], out);
  if(crng.state[12] == 0)
    crng.state[13]++;
  halvm_release_lock(&crng.lock);
}

/*
 * Use the leftover bytes from the CRNG block output (if there is
 * enough) to mutate the CRNG key to provide backtracking protection.
 */
static void crng_backtrack_protect(uint8_t tmp[CHACHA20_BLOCK_SIZE], int used)
{
  uint32_t *s, *d;
  int i;

  used = round_up(used, sizeof(uint32_t));
  if (used + CHACHA20_KEY_SIZE > CHACHA20_BLOCK_SIZE) {
    _extract_crng(tmp);
    used = 0;
  }
  halvm_acquire_lock(&crng.lock);
  s = (uint32_t*)&tmp[used];
  d = &crng.state[4];
  for (i=0; i < 8; i++)
    *d++ ^= *s++;
  halvm_release_lock(&crng.lock);
}

/*
 * Extract as many bytes as desired from the CRNG into a user-supplied buffer.
 * mix any extra bytes extracted back into the state.
 */
static ssize_t extract_crng(void *_buf, size_t nbytes)
{
  ssize_t ret = 0, i = CHACHA20_BLOCK_SIZE;
  uint8_t tmp[CHACHA20_BLOCK_SIZE];
  uint8_t *buf = _buf;

  while (nbytes) {
    _extract_crng(tmp);
    i = min(nbytes, CHACHA20_BLOCK_SIZE);
    memcpy(buf, tmp, i);

    nbytes -= i;
    buf    += i;
    ret    += i;
  }
  crng_backtrack_protect(tmp, i);

  /* Wipe data just written to memory */
  memset(tmp, 0, sizeof(tmp));

  return ret;
}

#endif /* URANDOM */
