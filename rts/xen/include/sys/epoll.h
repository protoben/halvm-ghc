#ifndef HALVM_EPOLL_H
#define HALVM_EPOLL_H

typedef union epoll_data {
  void     *ptr;
  int       fd;
  uint32_t  u32;
  uint64_t  u64;
} epoll_data_t;

struct epoll_event {
  uint32_t     events;
  epoll_data_t data;
};

#define EPOLL_CTL_ADD     1
#define EPOLL_CTL_DEL     2
#define EPOLL_CTL_MOD     3

#define EPOLLIN           0x1
#define EPOLLOUT          0x4
#define EPOLLERR          0x8
#define EPOLLHUP          0x10
#define EPOLLONESHOT      (1u << 30)

#endif
