#define __XEN__
#include <stdint.h>
#include <stdlib.h>
#include <alloca.h>
#include <xen/xen.h>
#include <xen/grant_table.h>
#include "grants.h"
#include "hypercalls.h"
#include <assert.h>
#include "memory.h"

static grant_entry_v2_t *grant_table = NULL;

void init_grants(void)
{
  gnttab_set_version_t version = { .version = 2 };
  gnttab_query_size_t  qsize   = { .dom = DOMID_SELF };
  gnttab_setup_table_t stable  = { .dom = DOMID_SELF };
  mfn_t *frames;

  assert(HYPERCALL_grant_table_op(GNTTABOP_set_version, &version, 1) >= 0);
  assert(HYPERCALL_grant_table_op(GNTTABOP_query_size, &qsize, 1) >= 0);
  frames = alloca(qsize.max_nr_frames * sizeof(mfn_t));
  stable.nr_frames = qsize.max_nr_frames;
  stable.frame_list.p = frames;
  assert(HYPERCALL_grant_table_op(GNTTABOP_setup_table, &stable, 1) >= 0);
  grant_table = map_frames(frames, qsize.max_nr_frames);
}
