#ifndef __SYSCALLSNOOP_H__
#define __SYSCALLSNOOP_H__

#include "vmlinux.h"
#include "missing_defines.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#include "common.bpf.h"


#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

#define NULL ((void *)0)

#define MAX_PERCPU_BUFSIZE  (1 << 15)     // This value is actually set by the kernel as an upper bound
#define MAX_STRING_SIZE     4096          // Choosing this value to be the same as PATH_MAX
#define MAX_STR_ARR_ELEM    40            // String array elements number should be bounded due to instructions limit
#define MAX_PATH_PREF_SIZE  64            // Max path prefix should be bounded due to instructions limit


// buffer overview: submit---string---file
#define SUBMIT_BUF_IDX      0
#define STRING_BUF_IDX      1
#define FILE_BUF_IDX        2
#define MAX_BUFFERS         3

#define CONFIG_SHOW_SYSCALL     0
#define CONFIG_EXEC_ENV         1
#define CONFIG_CAPTURE_FILES    2
#define CONFIG_EXTRACT_DYN_CODE 3

#define NONE_T        0UL
#define INT_T         1UL
#define UINT_T        2UL
#define LONG_T        3UL
#define ULONG_T       4UL
#define OFF_T_T       5UL
#define MODE_T_T      6UL
#define DEV_T_T       7UL
#define SIZE_T_T      8UL
#define POINTER_T     9UL
#define STR_T         10UL
#define STR_ARR_T     11UL
#define SOCKADDR_T    12UL
#define ALERT_T       13UL
#define TYPE_MAX      255UL

#if defined(bpf_target_x86)
#define PT_REGS_PARM6(ctx)  ((ctx)->r9)
#elif defined(bpf_target_arm64)
#define PT_REGS_PARM6(x) (((PT_REGS_ARM64 *)(x))->regs[5])
#endif
/*====================================SYSCALL CALLS =================================*/

#define TAG_NONE           0UL

#if defined(bpf_target_x86)
#define SYS_OPEN              2
#define SYS_MMAP              9
#define SYS_MPROTECT          10
#define SYS_RT_SIGRETURN      15
#define SYS_CLONE             56
#define SYS_FORK              57
#define SYS_VFORK             58
#define SYS_EXECVE            59
#define SYS_EXIT              60
#define SYS_EXIT_GROUP        231
#define SYS_OPENAT            257
#define SYS_EXECVEAT          322
#elif defined(bpf_target_arm64)
#define SYS_OPEN              1000 // undefined in arm64
#define SYS_MMAP              222
#define SYS_MPROTECT          226
#define SYS_RT_SIGRETURN      139
#define SYS_CLONE             220
#define SYS_FORK              1000 // undefined in arm64
#define SYS_VFORK             1000 // undefined in arm64
#define SYS_EXECVE            221
#define SYS_EXIT              93
#define SYS_EXIT_GROUP        94
#define SYS_OPENAT            56
#define SYS_EXECVEAT          281
#endif

#define RAW_SYS_ENTER         1000
#define RAW_SYS_EXIT          1001
#define DO_EXIT               1002
#define CAP_CAPABLE           1003
#define SECURITY_BPRM_CHECK   1004
#define SECURITY_FILE_OPEN    1005
#define SECURITY_INODE_UNLINK 1006
#define VFS_WRITE             1007
#define VFS_WRITEV            1008
#define MEM_PROT_ALERT        1009
#define SCHED_PROCESS_EXIT    1010
#define MAX_EVENT_ID          1011

/*=============================== INTERNAL STRUCTS ===========================*/

struct context_t {
    u64 ts;                     // Timestamp
    u32 pid;                    // PID as in the userspace term
    u32 tid;                    // TID as in the userspace term
    u32 ppid;                   // Parent PID as in the userspace term
    u32 uid;
    u32 mnt_id;
    u32 pid_id;
    char comm[TASK_COMM_LEN];
    char uts_name[TASK_COMM_LEN];
    u32 eventid;
    u8 argc;
    s64 retval;
};


struct args_t {
    unsigned long args[6];
};


struct buf_t {
    u8 buf[MAX_PERCPU_BUFSIZE];
};

struct syscall_data_t {
    uint id;                       // Current syscall id
    struct args_t args;                   // Syscall arguments
    unsigned long ts;              // Timestamp of syscall entry
    unsigned long ret;             // Syscall ret val. May be used by syscall exit tail calls.
};


/*=================================== MAPS =====================================*/
// Various configurations
BPF_HASH(config_map, u32, u32);
// Various configurations
BPF_HASH(chosen_events_map, u32, u32);
// Save container pid namespaces
BPF_HASH(containers_map, u32, u32);
// Persist args info between function entry and return
BPF_HASH(args_map, u64, struct args_t);
// Percpu global buffer variables
BPF_PERCPU_ARRAY(bufs, struct buf_t, MAX_BUFFERS);
// Holds offsets to bufs respectively
BPF_PERCPU_ARRAY(bufs_off, u32, MAX_BUFFERS);
// Encoded parameters types for event
BPF_HASH(params_types_map, u32, u64); 
// Encoded parameters names for event                  
BPF_HASH(params_names_map, u32, u64);
// Map 32bit syscalls numbers to 64bit syscalls numbers                   
BPF_HASH(sys_32_to_64_map, u32, u32);

/*================================== EVENTS ====================================*/
BPF_PERF_OUTPUT(events);

/*================ KERNEL VERSION DEPENDANT HELPER FUNCTIONS =================*/

static __always_inline u32 get_mnt_ns_id(struct nsproxy *ns)
{
    struct mnt_namespace* mntns = READ_KERN(ns->mnt_ns);
    return READ_KERN(mntns->ns.inum);
}

static __always_inline u32 get_pid_ns_id(struct nsproxy *ns)
{
    struct pid_namespace* pidns = READ_KERN(ns->pid_ns_for_children);
    return READ_KERN(pidns->ns.inum);
}

static __always_inline u32 get_uts_ns_id(struct nsproxy *ns)
{
    struct uts_namespace* uts_ns = READ_KERN(ns->uts_ns);
    return READ_KERN(uts_ns->ns.inum);
}

static __always_inline u32 get_ipc_ns_id(struct nsproxy *ns)
{
    struct ipc_namespace* ipc_ns = READ_KERN(ns->ipc_ns);
    return READ_KERN(ipc_ns->ns.inum);
}

static __always_inline u32 get_net_ns_id(struct nsproxy *ns)
{
    struct net* net_ns = READ_KERN(ns->net_ns);
    return READ_KERN(net_ns ->ns.inum);
}

static __always_inline u32 get_cgroup_ns_id(struct nsproxy *ns)
{
    struct cgroup_namespace* cgroup_ns = READ_KERN(ns->cgroup_ns);
    return READ_KERN(cgroup_ns->ns.inum);
}

static __always_inline u32 get_task_mnt_ns_id(struct task_struct *task)
{
    return get_mnt_ns_id(READ_KERN(task->nsproxy));
}

static __always_inline u32 get_task_pid_ns_id(struct task_struct *task)
{
    return get_pid_ns_id(READ_KERN(task->nsproxy));
}

static __always_inline u32 get_task_uts_ns_id(struct task_struct *task)
{
    return get_uts_ns_id(READ_KERN(task->nsproxy));
}

static __always_inline u32 get_task_ipc_ns_id(struct task_struct *task)
{
    return get_ipc_ns_id(READ_KERN(task->nsproxy));
}

static __always_inline u32 get_task_net_ns_id(struct task_struct *task)
{
    return get_net_ns_id(READ_KERN(task->nsproxy));
}

static __always_inline u32 get_task_cgroup_ns_id(struct task_struct *task)
{
    return get_cgroup_ns_id(READ_KERN(task->nsproxy));
}

static __always_inline u32 get_task_ns_pid(struct task_struct *task)
{
    int nr = 0;
    struct nsproxy *namespaceproxy = READ_KERN(task->nsproxy);
    struct pid_namespace *pid_ns_children = READ_KERN(namespaceproxy->pid_ns_for_children);
    unsigned int level = READ_KERN(pid_ns_children->level);

    if (bpf_core_type_exists(struct pid_link)) {
        struct task_struct___older_v50 *t = (void *) task;
        struct pid_link *pl = READ_KERN(t->pids);
        struct pid *p = READ_KERN(pl[PIDTYPE_MAX].pid);
        nr = READ_KERN(p->numbers[level].nr);
    } else {
        struct pid *tpid = READ_KERN(task->thread_pid);
        nr = READ_KERN(tpid->numbers[level].nr);
    }

    return nr;
}

static __always_inline u32 get_task_ns_tgid(struct task_struct *task)
{
    int nr = 0;
    struct nsproxy *namespaceproxy = READ_KERN(task->nsproxy);
    struct pid_namespace *pid_ns_children = READ_KERN(namespaceproxy->pid_ns_for_children);
    unsigned int level = READ_KERN(pid_ns_children->level);
    struct task_struct *group_leader = READ_KERN(task->group_leader);

    if (bpf_core_type_exists(struct pid_link)) {
        struct task_struct___older_v50 *gl = (void *) group_leader;
        struct pid_link *pl = READ_KERN(gl->pids);
        struct pid *p = READ_KERN(pl[PIDTYPE_MAX].pid);
        nr = READ_KERN(p->numbers[level].nr);
    } else {
        struct pid *tpid = READ_KERN(group_leader->thread_pid);
        nr = READ_KERN(tpid->numbers[level].nr);
    }
    return nr;
}

static __always_inline u32 get_task_ns_ppid(struct task_struct *task)
{
    int nr = 0;
    struct task_struct *real_parent = READ_KERN(task->real_parent);
    struct nsproxy *namespaceproxy = READ_KERN(real_parent->nsproxy);
    struct pid_namespace *pid_ns_children = READ_KERN(namespaceproxy->pid_ns_for_children);
    unsigned int level = READ_KERN(pid_ns_children->level);
    if (bpf_core_type_exists(struct pid_link)) {
        struct task_struct___older_v50 *rp = (void *) real_parent;
        struct pid_link *pl = READ_KERN(rp->pids);
        struct pid *p = READ_KERN(pl[PIDTYPE_MAX].pid);
        nr = READ_KERN(p->numbers[level].nr);
    } else {
        struct pid *tpid = READ_KERN(real_parent->thread_pid);
        nr = READ_KERN(tpid->numbers[level].nr);
    }

    return nr;
}

static __always_inline char * get_task_uts_name(struct task_struct *task)
{
    struct nsproxy *np = READ_KERN(task->nsproxy);
    struct uts_namespace *uts_ns = READ_KERN(np->uts_ns);
    return READ_KERN(uts_ns->name.nodename);
}

static __always_inline u32 get_task_ppid(struct task_struct *task)
{
    struct task_struct *parent = READ_KERN(task->real_parent);
    return READ_KERN(parent->tgid);
}

static __always_inline u64 get_task_start_time(struct task_struct *task)
{
    return READ_KERN(task->start_time);
}

static __always_inline u32 get_task_host_pid(struct task_struct *task)
{
    return READ_KERN(task->pid);
}

static __always_inline u32 get_task_host_tgid(struct task_struct *task)
{
    return READ_KERN(task->tgid);
}

static __always_inline struct task_struct * get_parent_task(struct task_struct *task)
{
    return READ_KERN(task->real_parent);
}

static __always_inline u32 get_task_exit_code(struct task_struct *task)
{
    return READ_KERN(task->exit_code);
}

static __always_inline int get_task_parent_flags(struct task_struct *task)
{
    struct task_struct *parent = READ_KERN(task->real_parent);
    return READ_KERN(parent->flags);
}

static __always_inline const struct cred *get_task_real_cred(struct task_struct *task)
{
    return READ_KERN(task->real_cred);
}

static __always_inline const char * get_binprm_filename(struct linux_binprm *bprm)
{
    return READ_KERN(bprm->filename);
}

static __always_inline const char * get_cgroup_dirname(struct cgroup *cgrp)
{
    struct kernfs_node *kn = READ_KERN(cgrp->kn);

    if (kn == NULL)
        return NULL;

    return READ_KERN(kn->name);
}

static __always_inline const u64 get_cgroup_id(struct cgroup *cgrp)
{
    struct kernfs_node *kn = READ_KERN(cgrp->kn);

    if (kn == NULL)
        return 0;

    u64 id; // was union kernfs_node_id before 5.5, can read it as u64 in both situations

    if (bpf_core_type_exists(union kernfs_node_id)) {
        struct kernfs_node___older_v55 *kn_old = (void *)kn;
        struct kernfs_node___rh8 *kn_rh8 = (void *)kn;

        if (bpf_core_field_exists(kn_rh8->id)) {
            // RHEL8 has both types declared: union and u64:
            //     kn->id
            //     rh->rh_kabi_hidden_172->id
            // pointing to the same data
            bpf_core_read(&id, sizeof(u64), &kn_rh8->id);
        } else {
            // all other regular kernels bellow v5.5
            bpf_core_read(&id, sizeof(u64), &kn_old->id);
        }

    } else {
        // kernel v5.5 and above
        bpf_core_read(&id, sizeof(u64), &kn->id);
    }

    return id;
}

static __always_inline const u32 get_cgroup_hierarchy_id(struct cgroup *cgrp)
{
    struct cgroup_root *root = READ_KERN(cgrp->root);
    return READ_KERN(root->hierarchy_id);
}

static __always_inline const u64 get_cgroup_v1_subsys0_id(struct task_struct *task)
{
    struct css_set *cgroups = READ_KERN(task->cgroups);
    struct cgroup_subsys_state *subsys0 = READ_KERN(cgroups->subsys[0]);
    struct cgroup *cgroup = READ_KERN(subsys0->cgroup);
    return get_cgroup_id(cgroup);
}

static __always_inline bool is_x86_compat(struct task_struct *task)
{
#if defined(bpf_target_x86)
    return READ_KERN(task->thread_info.status) & TS_COMPAT;
#else
    return false;
#endif
}

static __always_inline bool is_arm64_compat(struct task_struct *task)
{
#if defined(bpf_target_arm64)
    return READ_KERN(task->thread_info.flags) & _TIF_32BIT;
#else
    return false;
#endif
}

static __always_inline bool is_compat(struct task_struct *task)
{
#if defined(bpf_target_x86)
    return is_x86_compat(task);
#elif defined(bpf_target_arm64)
    return is_arm64_compat(task);
#else
    return false;
#endif
}

#endif