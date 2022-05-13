#ifndef _MISSING_DEFINES_H_
#define _MISSING_DEFINES_H_

#define  TS_COMPAT   0x0002
#define TIF_32BIT       22  /* 32bit process */
#define _TIF_32BIT      (1 << TIF_32BIT)

#define __user

/* Supported address families. */
#define AF_UNSPEC      0
#define AF_UNIX        1          /* Unix domain sockets */
#define AF_LOCAL       1          /* POSIX name for AF_UNIX */
#define AF_INET        2          /* Internet IP Protocol */
#define AF_AX25        3          /* Amateur Radio AX.25 */
#define AF_IPX         4          /* Novell IPX */
#define AF_APPLETALK   5          /* AppleTalk DDP */
#define AF_NETROM      6          /* Amateur Radio NET/ROM */
#define AF_BRIDGE      7          /* Multiprotocol bridge */
#define AF_ATMPVC      8          /* ATM PVCs */
#define AF_X25         9          /* Reserved for X.25 project */
#define AF_INET6       10         /* IP version 6 */
#define AF_ROSE        11         /* Amateur Radio X.25 PLP */
#define AF_DECnet      12         /* Reserved for DECnet project */
#define AF_NETBEUI     13         /* Reserved for 802.2LLC project */
#define AF_SECURITY    14         /* Security callback pseudo AF */
#define AF_KEY         15         /* PF_KEY key management API */
#define AF_NETLINK     16
#define AF_ROUTE       AF_NETLINK /* Alias to emulate 4.4BSD */
#define AF_PACKET      17         /* Packet family */
#define AF_ASH         18         /* Ash */
#define AF_ECONET      19         /* Acorn Econet */
#define AF_ATMSVC      20         /* ATM SVCs */
#define AF_RDS         21         /* RDS sockets */
#define AF_SNA         22         /* Linux SNA Project (nutters!) */
#define AF_IRDA        23         /* IRDA sockets */
#define AF_PPPOX       24         /* PPPoX sockets */
#define AF_WANPIPE     25         /* Wanpipe API Sockets */
#define AF_LLC         26         /* Linux LLC */
#define AF_IB          27         /* Native InfiniBand address */
#define AF_MPLS        28         /* MPLS */
#define AF_CAN         29         /* Controller Area Network */
#define AF_TIPC        30         /* TIPC sockets */
#define AF_BLUETOOTH   31         /* Bluetooth sockets */
#define AF_IUCV        32         /* IUCV sockets */
#define AF_RXRPC       33         /* RxRPC sockets */
#define AF_ISDN        34         /* mISDN sockets */
#define AF_PHONET      35         /* Phonet sockets */
#define AF_IEEE802154  36         /* IEEE802154 sockets */
#define AF_CAIF        37         /* CAIF sockets */
#define AF_ALG         38         /* Algorithm sockets */
#define AF_NFC         39         /* NFC sockets */
#define AF_VSOCK       40         /* vSockets */
#define AF_KCM         41         /* Kernel Connection Multiplexor */
#define AF_QIPCRTR     42         /* Qualcomm IPC Router */
#define AF_SMC         43         /* smc sockets: reserve number for PF_SMC protocol family that reuses AF_INET address family */

#pragma clang attribute push (__attribute__((preserve_access_index)), apply_to = record)

// (struct kernfs_node *)->id was union kernfs_node_id before 5.5

union kernfs_node_id {
    struct {
        u32 ino;
        u32 generation;
    };
    u64 id;
};

struct kernfs_node___older_v55 {
    const char *name;
    union kernfs_node_id id;
};

struct kernfs_node___rh8 {
    const char *name;
    union {
        u64 id;
        struct {
            union kernfs_node_id id;
        } rh_kabi_hidden_172;
        union { };
    };
};

// commit bf9765145b85 ("sock: Make sk_protocol a 16-bit value")

struct sock___old {
    struct sock_common  __sk_common;
    unsigned int        __sk_flags_offset[0];
    unsigned int        sk_padding : 1,
                        sk_kern_sock : 1,
                        sk_no_check_tx : 1,
                        sk_no_check_rx : 1,
                        sk_userlocks : 4,
                        sk_protocol  : 8,
                        sk_type      : 16;
    u16                 sk_gso_max_segs;
};

// support bpf_core_type_exists((task struct)->pids) for kernels < 5.0

struct pid_link
{
    struct hlist_node node;
    struct pid *pid;
};

struct task_struct___older_v50 {
    struct pid_link pids[PIDTYPE_MAX];
};

#pragma clang attribute pop

#endif