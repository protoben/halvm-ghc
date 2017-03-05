#ifndef RTS_XEN_GRANTS_H
#define RTS_XEN_GRANTS_H

#ifndef __XEN__
#define __XEN__
#endif

#include <xen/xen.h>
#include <xen/grant_table.h>

void init_grants(void);

long alloc_grant(domid_t, void *, uint16_t, int, grant_ref_t *);
long end_grant(grant_ref_t);

long map_grants(domid_t,int,grant_ref_t*,size_t,void**,uint32_t*,uint64_t*);
long unmap_grants(grant_handle_t *, size_t);

long prepare_transfer(domid_t);
long transfer_frame(domid_t, grant_ref_t, void*);
long complete_transfer(grant_ref_t, int);
long copy_frame(unsigned long src, int src_is_ref, domid_t sdom, uint16_t soff,
                unsigned long dst, int dst_is_ref, domid_t ddom, uint16_t doff,
                uint16_t length);

#endif
