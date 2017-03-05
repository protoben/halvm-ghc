#ifdef PROFILING
#include <runtime_reqs.h>
#include <errno.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <assert.h>
#define XEN_HAVE_PV_GUEST_ENTRY 1
#include <xen/xen.h>
#include <xen/io/xenbus.h>
#include <xen/io/xs_wire.h>
#include <xen/io/blkif.h>
#include <signals.h>
#include <grants.h>
#include <memory.h>
#include <vmm.h>

#ifdef __x86_64__
#define wmb() asm volatile ("sfence"                  : : : "memory")
#define rmb() asm volatile ("lfence"                  : : : "memory")
#define  mb() asm volatile ("mfence"                  : : : "memory")
#else
#define wmb() asm volatile (""                        : : : "memory")
#define rmb() asm volatile ("lock; addl $0, 0(%%esp)" : : : "memory")
#define  mb() asm volatile ("lock; addl $0, 0(%%esp)" : : : "memory")
#endif

struct FILE {
  size_t              fsize;
  size_t              cur_block_num;
  size_t              cur_block_off;
  grant_ref_t         ring_grant, block_grant;
  uint32_t            chan;
  char               *block;
  blkif_vdev_t        disk_handle;
  blkif_front_ring_t  ring;
};

struct xenStorePaths {
  char   *feDir;
  char   *beDir;
};
typedef struct xenStorePaths XenStorePaths;

extern struct start_info                *system_start_info;
static struct xenstore_domain_interface *xsint             = NULL;

static int            push_out_block(FILE *p, int closed);
static int            write_block(FILE *p, blkif_sector_t, size_t);
static XenStorePaths *find_xs_paths(char *, char *, uint32_t);

static char          *xenstore_getkey(char *);
static long           xenstore_setkey(char *, char *, size_t);
static uint32_t       xenstore_write(uint32_t, uint32_t, void *);
static uint32_t       xenstore_read(uint32_t, uint32_t *, void **);

#define min(a,b) ((a) < (b) ? (a) : (b))

static void handler(int x __attribute__((unused))) { }

FILE *profile_fopen(const char *fname, const char *mode)
{
  char *key = NULL, *val = NULL, *rsp = NULL, *domStr = NULL, *diskname = NULL;
  uint32_t req, rsptype, rsplen, domId;
  XenStorePaths *xsp = NULL;
  uint64_t store_mptr;
  FILE *retval = NULL;
  int vallen;
  long res;

  if(strncmp(mode, "w", 1) != 0)
    goto fail;

  if(strncmp(fname, "HaLVM.prof", 11) == 0)
    diskname = "xvdp1";
  if(strncmp(fname, "HaLVM.hp", 9) == 0)
    diskname = "xvdp2";
  if(!diskname)
    goto fail;

  store_mptr = (uint64_t)system_start_info->store_mfn << 12;
  unmask_channel(system_start_info->store_evtchn);
  xsint = (struct xenstore_domain_interface*)machine_to_virtual(store_mptr);
  if(!xsint) {
    printf("PROFILING ERROR: Could not map XenStore page.\n");
    goto fail;
  }

  /* Try to run "ls devices/vbd" */
  req = xenstore_write(XS_DIRECTORY, strlen("device/vbd") + 1, "device/vbd");
  rsplen = xenstore_read(req, &rsptype, (void**)&rsp);
  if(rsptype == XS_ERROR) {
    printf("PROFILING: XenStore read error. Did you forget to add a disk?\n");
    goto fail;
  }
  if(rsptype != XS_DIRECTORY) {
    printf("PROFILING: XenStore has gone weird. Giving up.\n");
    goto fail;
  }

  /* Find the XenStore paths associated with the disk we want */
  xsp = find_xs_paths(diskname, rsp, rsplen);
  if(!xsp) {
    printf("PROFILING: Couldn't find file to open.\n");
    goto fail;
  }

  /* Pull out the other's domId */
  key = malloc(256);
  snprintf(key, 256, "%s/backend-id", xsp->feDir);
  domStr = xenstore_getkey(key);
  domId = atoi(domStr);

  /* allocate the return structure and buffers */
  retval = malloc(sizeof(FILE));
  if(!retval)
    goto fail;
  memset(retval, 0, sizeof(FILE));
  retval->cur_block_num = 1;
  retval->block = runtime_alloc(NULL, 4096, PROT_READ|PROT_WRITE);
  if(!retval->block)
    goto fail;
  assert( (((uintptr_t)retval->block) & 4095) == 0 );
  retval->ring.sring = runtime_alloc(NULL, 4096, PROT_READ|PROT_WRITE);
  if(!retval->ring.sring)
    goto fail;
  assert( (((uintptr_t)retval->ring.sring) & 4095) == 0 );
  SHARED_RING_INIT(retval->ring.sring);
  FRONT_RING_INIT(&(retval->ring), retval->ring.sring, 4096);

  /* get the device handle */
  snprintf(key, 256, "%s/virtual-device", xsp->feDir);
  val = xenstore_getkey(key);
  retval->disk_handle = atoi(val);

  /* allocate the grant references and event channel */
  res = alloc_grant(domId, retval->ring.sring, 4096, 0, &retval->ring_grant);
  if(res) {
    printf("PROFILING: Failed to allocate ring grant reference: %d\n", res);
    goto fail;
  }
  res = alloc_grant(domId, retval->block, 4096, 0, &retval->block_grant);
  if(res) {
    printf("PROFILING: Failed to allocate block grant reference: %d\n", res);
    goto fail;
  }
  res = channel_alloc(DOMID_SELF, domId);
  if(res < 0) {
    printf("PROFILING: Failed to allocate grant reference: %d\n", res);
    goto fail;
  }
  retval->chan = (uint32_t)res;
  set_c_handler(retval->chan, handler);

  /* write them into our tree */
  val    = malloc(256);
  /*    */ snprintf(key, 256, "%s/ring-ref", xsp->feDir);
  vallen = snprintf(val, 256, "%d", retval->ring_grant);
  if(!xenstore_setkey(key, val, vallen)) goto fail;
  /*    */ snprintf(key, 256, "%s/event-channel", xsp->feDir);
  vallen = snprintf(val, 256, "%d", retval->chan);
  if(!xenstore_setkey(key, val, vallen)) goto fail;
  /*    */ snprintf(key, 256, "%s/state", xsp->feDir);
  vallen = snprintf(val, 256, "%d", XenbusStateInitialised);
  if(!xenstore_setkey(key, val, vallen)) goto fail;

  /* wait for the other side to sync up */
  do {
    char *state;

    runtime_block(1);
    snprintf(key, 256, "%s/state", xsp->beDir);
    state = xenstore_getkey(key);
    res = atoi(state);
    free(state);
  } while(res != XenbusStateConnected);

  /* write out that we're good */
  /*    */ snprintf(key, 256, "%s/state", xsp->feDir);
  vallen = snprintf(val, 256, "%d", XenbusStateConnected);
  if(!xenstore_setkey(key, val, vallen)) goto fail;

  return retval;

fail:
  if(key) free(key);
  if(val) free(val);
  if(rsp) free(rsp);
  if(xsp) {
    free(xsp->feDir);
    free(xsp->beDir);
    free(xsp);
  }
  if(domStr) free(domStr);
  if(retval) {
    if(retval->block_grant) end_grant(retval->block_grant);
    if(retval->ring_grant) end_grant(retval->ring_grant);
    if(retval->block) runtime_free(retval->block, 4096);
    if(retval->ring.sring) runtime_free(retval->ring.sring, 4096);
    if(retval->chan) channel_close(retval->chan);
    free(retval);
  }
  errno = -EACCES;
  return NULL;
}

void profile_write(FILE *p, void *buf, int amt)
{
  while(p->cur_block_off + amt > 4096) {
    int amt1 = 4096 - p->cur_block_off;
    memcpy(p->block + p->cur_block_off, buf, amt1);
    p->fsize         += amt1;
    p->cur_block_off  = 4096;
    push_out_block(p, 0);

    buf = (void*)((uintptr_t)buf + amt1);
    amt = amt - amt1;
  }

  memcpy(p->block + p->cur_block_off, buf, amt);
  p->fsize         += amt;
  p->cur_block_off += amt;

  if(p->cur_block_off == 4096)
    push_out_block(p, 0);
}

void profile_flush(FILE *p)
{
  if(p->cur_block_off) {
    void *copy = malloc(p->cur_block_off);
    size_t copy_size = p->cur_block_off;
    size_t skip_amt, i;

    memcpy(copy, p->block, p->cur_block_off);
    write_block(p, p->cur_block_num, p->cur_block_off);
    for(i = 0; i < 512 / sizeof(size_t); i += 2) {
      ((size_t*)p->block)[i+0] = p->fsize ^ i;
      ((size_t*)p->block)[i+1] = 0        ^ i;
    }
    write_block(p, 0, 512);
    skip_amt = (copy_size / 512) * 512;
    p->cur_block_num += copy_size / 512;
    p->cur_block_off  = copy_size % 512;
    memcpy(p->block, (void*)((uintptr_t)copy + skip_amt), p->cur_block_off);
    free(copy);
  }
}

void profile_fclose(FILE *p)
{
  push_out_block(p, 1);
}

/******************************************************************************
 ******************************************************************************/

/* WARNING WARNING WARNING: This overwrites the data in FILE->block */
static int push_out_block(FILE *p, int closed)
{
  size_t i;
  int res;

  assert( (p->cur_block_off % 512 == 0) || closed );
  /* write out the block, if there's any data */
  if(p->cur_block_off) {
    res = write_block(p, p->cur_block_num, p->cur_block_off);
    if(!res) return 0;
  }
  /* write out the new header */
  for(i = 0; i < 512 / sizeof(size_t); i += 2) {
    ((size_t*)p->block)[i+0] = p->fsize ^ i;
    ((size_t*)p->block)[i+1] = closed   ^ i;
  }
  res = write_block(p, 0, 512);
  if(!res) return 0;
  /* reinitialize the state */
  memset(p->block, 0, 4096);
  p->cur_block_num += p->cur_block_off / 512;
  p->cur_block_off  = 0;

  return 1;
}

static int write_block(FILE *p, blkif_sector_t sector, size_t amt)
{
  static uint64_t next_reqid = 1;
  blkif_response_t *rsp;
  blkif_request_t *req;
  int notify, work_to_do;
  uint64_t reqid;
  RING_IDX i;

  /* wait until we can write something */
  while(RING_FULL(&p->ring)) runtime_block(1);

  /* write out the request */
  i = p->ring.req_prod_pvt++;
  req = RING_GET_REQUEST(&p->ring, i);
  memset(req, 0, sizeof(blkif_request_t));
  req->operation         = BLKIF_OP_WRITE;
  req->nr_segments       = 1;
  req->handle            = p->disk_handle;
  req->id                = reqid = next_reqid++;
  req->sector_number     = sector;
  req->seg[0].gref       = p->block_grant;
  req->seg[0].first_sect = 0;
  req->seg[0].last_sect  = (amt - 1) / 512;
  wmb();
  RING_PUSH_REQUESTS_AND_CHECK_NOTIFY(&p->ring, notify);
  if(notify) channel_send(p->chan);

  /* wait for it to be satisfied */
  do {
    while(!RING_HAS_UNCONSUMED_RESPONSES(&p->ring))
      runtime_block(1);
    i = p->ring.rsp_cons++;
    rsp = RING_GET_RESPONSE(&p->ring, i);
  } while(rsp->id != reqid);

  /* was it successful? */
  if(rsp->status != BLKIF_RSP_OKAY) {
    printf("PROFILING: Block write failed!\n");
    return 0;
  }

  /* we do writes one at a time, synchronously, so work_to_do should always
     be false */
  RING_FINAL_CHECK_FOR_RESPONSES(&p->ring, work_to_do);
  assert(!work_to_do);

  return 1;
}

static XenStorePaths *find_xs_paths(char *fname, char *dir, uint32_t dirlen)
{
  uint32_t i;
  char *cur;

  /* parse the responses, trying to find one with the name 'HaLVM.prof' */
  for(i = dirlen, cur = dir; i > 0; ) {
    char *key = malloc(256), *backend, *dev;

    /* get the backend key */
    snprintf(key, 256, "device/vbd/%s/backend", cur);
    backend = xenstore_getkey(key);
    if(!backend) continue;

    /* get the device name */
    snprintf(key, 256, "%s/dev", backend);
    dev = xenstore_getkey(key);
    if(!dev) continue;

    /* is this what we're looking for */
    if(strncmp(fname, dev, strlen(fname)) == 0) {
      XenStorePaths *out = malloc(sizeof(XenStorePaths));

      out->feDir = malloc(256);
      snprintf(out->feDir, 256, "device/vbd/%s", cur);
      out->beDir = backend;

      free(key);
      free(dev);

      return out;
    }

    /* advance to the next word */
    while( (i > 0) && (cur[0] != 0) ) { i -= 1; cur += 1; }
    if(i > 0) { i -= 1; cur += 1; }
  }

  return NULL;
}

/******************************************************************************
 ******************************************************************************/

static char *xenstore_getkey(char *key)
{
  uint32_t req_id, type, len;
  char *res, *buffer;

  req_id = xenstore_write(XS_READ, strlen(key) + 1, key);
  len    = xenstore_read(req_id, &type, (void**)&buffer);
  if(type == XS_ERROR) {
    printf("PROFILING: Error reading key |%s|: %s\n", key, buffer);
    free(buffer);
    return NULL;
  }
  if(type != XS_READ) {
    printf("PROFILING: Error reading key |%s|: %d\n", key, type);
    free(buffer);
    return NULL;
  }

  /* the Xenstore doesn't send back 0-terminated values on reads, so
     make our result zero terminated */
  res = malloc(len + 1);
  memcpy(res, buffer, len);
  res[len] = 0;
  free(buffer);

  return res;
}

static long xenstore_setkey(char *key, char *val, size_t val_len)
{
  uint32_t req_id, key_len, res, type;
  char *outbuf, *resbuf;

  /* convert our inputs into KEY0VAL */
  key_len = strlen(key);
  outbuf = malloc(key_len + 1 + val_len);
  memcpy(outbuf, key, key_len);
  memcpy(outbuf + key_len + 1, val, val_len);
  outbuf[key_len] = 0;

  req_id = xenstore_write(XS_WRITE, key_len + 1 + val_len, outbuf);
  res = xenstore_read(req_id, &type, (void**)&resbuf);
  if(type == XS_ERROR) {
    printf("PROFILING: Error writing key |%s|: %s\n", key, resbuf);
    res = 0;
  } else if(type != XS_WRITE) {
    printf("PROFILING: Error writing key |%s|: %d\n", key, type);
    res = 0;
  } else res = 1;

  free(outbuf);
  free(resbuf);

  return res;
}

static uint32_t xenstore_write(uint32_t type, uint32_t len, void *inbuf)
{
  static uint32_t req_id = 1;
  struct xsd_sockmsg m;
  void *buffer, *cur;
  uint32_t prod;

  /* build out the header and adjust the final length */
  m.type   = type;
  m.req_id = req_id++;
  m.tx_id  = 0;
  m.len    = len;
  len += sizeof(struct xsd_sockmsg);

  /* wait until we can send out the data all at once */
  while( (XENSTORE_RING_SIZE - (xsint->req_prod - xsint->req_cons)) < len )
    runtime_block(1);
  assert( (xsint->req_prod + len - xsint->req_cons) < XENSTORE_RING_SIZE);

  /* Combine the data into one block */
  cur = buffer = malloc(len);
  memcpy(buffer, &m, sizeof(struct xsd_sockmsg));
  memcpy((void*)((uintptr_t)buffer + sizeof(struct xsd_sockmsg)), inbuf, m.len);

  /* dump it out to the ring */
  prod = xsint->req_prod;
  while(len != 0) {
    uint32_t nextbit = min(len, XENSTORE_RING_SIZE - MASK_XENSTORE_IDX(prod));
    memcpy(xsint->req + MASK_XENSTORE_IDX(prod), cur, nextbit);
    prod += nextbit;
    cur   = (void*)((uintptr_t)cur + nextbit);
    len  -= nextbit;
  }

  /* notify the other size */
  wmb();
  xsint->req_prod = prod;
  channel_send(system_start_info->store_evtchn);

  /* free our buffer and return the request id */
  free(buffer);
  return m.req_id;
}

static uint32_t xenstore_read(uint32_t req_id, uint32_t *rtype, void **buffer)
{
  struct xsd_sockmsg m;
  char *mbuf;
  uint32_t cons, i;

  *buffer = NULL; /* safety */
  *rtype  = 0xDEADBEEF;
again:
  /* wait until there's some data available */
  while( (xsint->rsp_prod - xsint->rsp_cons) < sizeof(struct xsd_sockmsg) )
    runtime_block(1);

  /* copy off the header */
  cons = xsint->rsp_cons;
  for(i = 0; i < sizeof(struct xsd_sockmsg); i++)
    ((char*)(&m))[i] = xsint->rsp[MASK_XENSTORE_IDX(cons++)];

  /* is this the item we were looking for? */
  if(m.req_id != req_id) {
    /* no ... so ignore this message and restart */
    cons += m.len;
    xsint->rsp_cons = cons;
    goto again;
  }

  /* it is! allocate and copy off the result */
  mbuf = malloc(m.len);
  while( (xsint->rsp_prod - cons) < m.len )
    runtime_block(1);
  for(i = 0; i < m.len; i++)
    mbuf[i] = xsint->rsp[MASK_XENSTORE_IDX(cons++)];

  /* update the other size and return the buffer and length */ 
  xsint->rsp_cons = cons;
  *buffer = mbuf;
  *rtype  = m.type;
  return m.len;
}
#endif
