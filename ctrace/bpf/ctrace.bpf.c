#include "ctrace.bpf.h"



/*============================ HELPER FUNCTIONS ==============================*/

static __always_inline int event_chosen(u32 key) {
    u32* config = bpf_map_lookup_elem(&chosen_events_map, &key);
    if (config == NULL)
        return 0;

    return *config;
}

static __always_inline int get_config(u32 key) {

    u32* config = bpf_map_lookup_elem(&config_map, &key);

    if (config == NULL)
        return 0;

    return *config;
}

static __always_inline int equality_filter_matches(int filter_config, void* filter_map, void* key) {
    int config = get_config(filter_config);
    if (!config)
        return 1;

    u32* equality = bpf_map_lookup_elem(filter_map, key);
    if (equality != NULL) {
        return *equality;
    }

    if (config == FILTER_IN)
        return 0;

    return 1;
}

static __always_inline int init_context(context_t* context) {
    struct task_struct* task;
    task = (struct task_struct*)bpf_get_current_task();

    u64 id = bpf_get_current_pid_tgid();
    context->host_tid = id;
    context->host_pid = id >> 32;
    context->host_ppid = get_task_ppid(task);
    context->tid = get_task_ns_pid(task);
    context->pid = get_task_ns_tgid(task);
    context->ppid = get_task_ns_ppid(task);
    context->mnt_id = get_task_mnt_ns_id(task);
    context->pid_id = get_task_pid_ns_id(task);
    context->uid = bpf_get_current_uid_gid();
    bpf_get_current_comm(&context->comm, sizeof(context->comm));
    char* uts_name = get_task_uts_name(task);
    if (uts_name) {
        bpf_probe_read_str(&context->uts_name, TASK_COMM_LEN, uts_name);
    }
    if (get_config(CONFIG_CGROUP_V1)) {
        context->cgroup_id = get_cgroup_v1_subsys0_id(task);
    }
    else {
        context->cgroup_id = bpf_get_current_cgroup_id();
    }
    // Save timestamp in microsecond resolution
    context->ts = bpf_ktime_get_ns();

    // Clean Stack Trace ID
    context->argc = 0;

    return 0;
}

static __always_inline buf_t* get_buf(int idx) {
    return bpf_map_lookup_elem(&bufs, &idx);
}

static __always_inline void set_buf_off(int buf_idx, u32 new_off) {
    bpf_map_update_elem(&bufs_off, &buf_idx, &new_off, BPF_ANY);
}

static __always_inline u32* get_buf_off(int buf_idx) {
    return bpf_map_lookup_elem(&bufs_off, &buf_idx);
}

// TODO save_to_buf
static __always_inline int save_to_buf(buf_t* submit_p, void* ptr, u32 size, u8 type, u8 tag) {
    // The biggest element that can be saved with this function should be defined here
#define MAX_ELEMENT_SIZE sizeof(struct sockaddr_un)
    if (type == 0)
        return 0;

    if (size == 0)
        return 0;

    u32* off = get_buf_off(SUBMIT_BUF_IDX);
    if (off == NULL)
        return 0;
    if (*off > MAX_PERCPU_BUFSIZE - MAX_ELEMENT_SIZE)
        // Satisfy validator for probe read
        return 0;

    // Save argument type
    int rc = bpf_probe_read(&(submit_p->buf[*off]), 1, &type);
    if (rc != 0)
        return 0;

    *off += 1;

    if (*off > MAX_PERCPU_BUFSIZE - MAX_ELEMENT_SIZE)
        // Satisfy validator for probe read
        return 0;

    // Save argument tag
    rc = bpf_probe_read(&(submit_p->buf[*off]), 1, &tag);
    if (rc != 0) {
        *off -= 1;
        return 0;
    }
    *off += 1;

    if (*off > MAX_PERCPU_BUFSIZE - MAX_ELEMENT_SIZE) {
        // Satisfy validator for probe read
        *off -= 2;
        return 0;
    }

    // Read into buffer
    rc = bpf_probe_read(&(submit_p->buf[*off]), size, ptr);
    if (rc == 0) {
        *off += size;
        return 1;
    }

    *off -= 2;
    return 0;
}


// Context will always be at the start of the submission buffer
// It may be needed to resave the context if the arguments number changed by logic
static __always_inline int save_context_to_buf(buf_t* submit_p, void* ptr) {
    //read the context struct to the beginning of the submit_p
    int rc = bpf_probe_read(&(submit_p->buf[0]), sizeof(context_t), ptr);
    //read successfully
    if (rc == 0)
        return sizeof(context_t);

    return 0;
}

static __always_inline context_t init_and_save_context(void* ctx, buf_t* submit_p, u32 id, u8 argnum, long ret) {
    context_t context = {};
    init_context(&context);
    context.eventid = id;
    context.argc = argnum;
    context.retval = ret;

    save_context_to_buf(submit_p, (void*)&context);
    // bpf_printk("init_and_save_context, argc=%d", context.argc);
    return context;
}

// TODO save_str_to_buf
static __always_inline int save_str_to_buf(buf_t* submit_p, void* ptr, u8 tag) {
    u32* off = get_buf_off(SUBMIT_BUF_IDX);
    if (off == NULL)
        return 0;
    if (*off > MAX_PERCPU_BUFSIZE - MAX_STRING_SIZE - sizeof(int))
        // not enough space - return
        return 0;

    // Save argument type
    u8 type = STR_T;
    bpf_probe_read(&(submit_p->buf[*off & (MAX_PERCPU_BUFSIZE - 1)]), 1, &type);

    *off += 1;

    // Save argument tag
    if (tag != TAG_NONE) {
        int rc = bpf_probe_read(&(submit_p->buf[*off & (MAX_PERCPU_BUFSIZE - 1)]), 1, &tag);
        if (rc != 0) {
            *off -= 1;
            return 0;
        }

        *off += 1;
    }

    if (*off > MAX_PERCPU_BUFSIZE - MAX_STRING_SIZE - sizeof(int)) {
        // Satisfy validator for probe read
        *off -= 2;
        return 0;
    }

    // Read into buffer
    int sz = bpf_probe_read_str(&(submit_p->buf[*off + sizeof(int)]), MAX_STRING_SIZE, ptr);
    if (sz > 0) {
        if (*off > MAX_PERCPU_BUFSIZE - sizeof(int)) {
            // Satisfy validator for probe read
            *off -= 2;
            return 0;
        }
        bpf_probe_read(&(submit_p->buf[*off]), sizeof(int), &sz);
        *off += sz + sizeof(int);
        return 1;
    }

    *off -= 2;
    return 0;
}

static __always_inline int save_str_arr_to_buf(buf_t* submit_p, const char __user* const __user* ptr, u8 tag) {
    // Data saved to submit buf: [type][tag][str count][str1 size][str1][str2 size][str2]...
    u8 elem_num = 0;

    u32* off = get_buf_off(SUBMIT_BUF_IDX);
    if (off == NULL)
        return 0;

    // mark string array start
    u8 type = STR_ARR_T;
    int rc = bpf_probe_read(&(submit_p->buf[*off & (MAX_PERCPU_BUFSIZE - 1)]), 1, &type);
    if (rc != 0)
        return 0;

    *off += 1;

    // Save argument tag
    rc = bpf_probe_read(&(submit_p->buf[*off & (MAX_PERCPU_BUFSIZE - 1)]), 1, &tag);
    if (rc != 0) {
        *off -= 1;
        return 0;
    }

    *off += 1;

    // Save space for number of elements
    u32 orig_off = *off;
    *off += 1;

#pragma unroll
    for (int i = 0; i < MAX_STR_ARR_ELEM; i++) {
        const char* argp = NULL;
        bpf_probe_read(&argp, sizeof(argp), &ptr[i]);
        if (!argp)
            goto out;

        if (*off > MAX_PERCPU_BUFSIZE - MAX_STRING_SIZE - sizeof(int))
            // not enough space - return
            goto out;

        // Read into buffer
        int sz = bpf_probe_read_str(&(submit_p->buf[*off + sizeof(int)]), MAX_STRING_SIZE, argp);
        if (sz > 0) {
            if (*off > MAX_PERCPU_BUFSIZE - sizeof(int))
                // Satisfy validator for probe read
                goto out;
            bpf_probe_read(&(submit_p->buf[*off]), sizeof(int), &sz);
            *off += sz + sizeof(int);
            elem_num++;
            continue;
        }
        else {
            goto out;
        }
    }
    // handle truncated argument list
    char ellipsis[] = "...";
    if (*off > MAX_PERCPU_BUFSIZE - MAX_STRING_SIZE - sizeof(int))
        // not enough space - return
        goto out;

    // Read into buffer
    int sz = bpf_probe_read_str(&(submit_p->buf[*off + sizeof(int)]), MAX_STRING_SIZE, ellipsis);
    if (sz > 0) {
        if (*off > MAX_PERCPU_BUFSIZE - sizeof(int))
            // Satisfy validator for probe read
            goto out;
        bpf_probe_read(&(submit_p->buf[*off]), sizeof(int), &sz);
        *off += sz + sizeof(int);
        elem_num++;
    }
out:
    // save number of elements in the array
    bpf_probe_read(&(submit_p->buf[orig_off & (MAX_PERCPU_BUFSIZE - 1)]), 1, &elem_num);
    return 1;
}

#define DEC_ARG(n, enc_arg) ((enc_arg>>(8*n))&0xFF)

static __always_inline int save_args_to_buf(u64 types, u64 tags, struct args_t* args) {
    unsigned int i;
    unsigned int rc = 0;
    unsigned int argc = 0;
    short family = 0;

    if (types == 0)
        return 0;

    buf_t* submit_p = get_buf(SUBMIT_BUF_IDX);
    if (submit_p == NULL)
        return 0;

#pragma unroll
    for (i = 0; i < 6; i++) {
        int size = 0;
        u8 type = DEC_ARG(i, types);
        u8 tag = DEC_ARG(i, tags);
        switch (type) {
        case NONE_T:
            break;
        case INT_T:
            size = sizeof(int);
            break;
        case UINT_T:
            size = sizeof(unsigned int);
            break;
        case OFF_T_T:
            size = sizeof(off_t);
            break;
        case DEV_T_T:
            size = sizeof(dev_t);
            break;
        case MODE_T_T:
            size = sizeof(mode_t);
            break;
        case LONG_T:
            size = sizeof(long);
            break;
        case ULONG_T:
            size = sizeof(unsigned long);
            break;
        case SIZE_T_T:
            size = sizeof(size_t);
            break;
        case POINTER_T:
            size = sizeof(void*);
            break;
        case STR_T:
            rc = save_str_to_buf(submit_p, (void*)args->args[i], tag);
            break;
        case SOCKADDR_T:
            if (args->args[i]) {
                bpf_probe_read(&family, sizeof(short), (void*)args->args[i]);
                switch (family) {
                case AF_UNIX:
                    size = sizeof(struct sockaddr_un);
                    break;
                case AF_INET:
                    size = sizeof(struct sockaddr_in);
                    break;
                case AF_INET6:
                    size = sizeof(struct sockaddr_in6);
                    break;
                default:
                    size = sizeof(short);
                }
                rc = save_to_buf(submit_p, (void*)(args->args[i]), size, type, tag);
            }
            else {
                rc = save_to_buf(submit_p, &family, sizeof(short), type, tag);
            }
            break;
        }
        if ((type != NONE_T) && (type != STR_T) && (type != SOCKADDR_T))
            rc = save_to_buf(submit_p, (void*)&(args->args[i]), size, type, tag);

        if (rc > 0) {
            argc++;
            rc = 0;
        }
    }

    return argc;
}

static __always_inline int events_perf_submit(void* ctx) {
    u32* off = get_buf_off(SUBMIT_BUF_IDX);
    if (off == NULL)
        return -1;
    buf_t* submit_p = get_buf(SUBMIT_BUF_IDX);
    if (submit_p == NULL)
        return -1;

    /* satisfy validator by setting buffer bounds */
    int size = ((*off - 1) & (MAX_PERCPU_BUFSIZE - 1)) + 1;
    void* data = submit_p->buf;
    return bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, data, size);
}

static __always_inline int save_args(struct args_t* args, u32 event_id) {
    u64 id = event_id;
    u32 tid = bpf_get_current_pid_tgid();
    id = id << 32 | tid;
    bpf_map_update_elem(&args_map, &id, args, BPF_ANY);

    return 0;
}

static __always_inline int save_args_from_regs(struct pt_regs* ctx, u32 event_id, bool is_syscall) {
    args_t args = {};

    struct task_struct* task = (struct task_struct*)bpf_get_current_task();
    if (is_x86_compat(task) && is_syscall) {
#if defined(bpf_target_x86)
        args.args[0] = ctx->bx;
        args.args[1] = ctx->cx;
        args.args[2] = ctx->dx;
        args.args[3] = ctx->si;
        args.args[4] = ctx->di;
        args.args[5] = ctx->bp;
#endif
    }
    else {
        args.args[0] = PT_REGS_PARM1(ctx);
        args.args[1] = PT_REGS_PARM2(ctx);
        args.args[2] = PT_REGS_PARM3(ctx);
        args.args[3] = PT_REGS_PARM4(ctx);
        args.args[4] = PT_REGS_PARM5(ctx);
        args.args[5] = PT_REGS_PARM6(ctx);
    }

    return save_args(&args, event_id);
}

static __always_inline int load_args(struct args_t* args, bool delete, u32 event_id) {
    struct args_t* saved_args;
    u32 tid = bpf_get_current_pid_tgid();
    u64 id = event_id;
    id = id << 32 | tid;

    saved_args = bpf_map_lookup_elem(&args_map, &id);
    if (saved_args == 0) {
        // missed entry or not a container
        return -1;
    }
    args->args[0] = saved_args->args[0];
    args->args[1] = saved_args->args[1];
    args->args[2] = saved_args->args[2];
    args->args[3] = saved_args->args[3];
    args->args[4] = saved_args->args[4];
    args->args[5] = saved_args->args[5];

    if (delete)
        bpf_map_delete_elem(&args_map, &id);

    return 0;
}

static __always_inline int del_args(u32 event_id) {
    u32 tid = bpf_get_current_pid_tgid();
    u64 id = event_id;
    id = id << 32 | tid;

    bpf_map_delete_elem(&args_map, &id);

    return 0;
}

static __always_inline int save_retval(u64 retval, u32 event_id) {
    u64 id = event_id;
    u32 tid = bpf_get_current_pid_tgid();
    id = id << 32 | tid;

    bpf_map_update_elem(&ret_map, &id, &retval, BPF_ANY);

    return 0;
}

static __always_inline int del_retval(u32 event_id) {
    u64 id = event_id;
    u32 tid = bpf_get_current_pid_tgid();
    id = id << 32 | tid;

    bpf_map_delete_elem(&ret_map, &id);

    return 0;
}

static __always_inline u32 add_pid() {
    u32 pid = bpf_get_current_pid_tgid();
    if (bpf_map_lookup_elem(&containers_map, &pid) == 0) {
        bpf_map_update_elem(&containers_map, &pid, &pid, BPF_ANY);
    }

    return pid;
}

static __always_inline u32 add_container_pid_ns() {
    struct task_struct* task;
    task = (struct task_struct*)bpf_get_current_task();

    u32 pid_ns = get_task_pid_ns_id(task);
    if (bpf_map_lookup_elem(&containers_map, &pid_ns) != 0)
        // Container pidns was already added to map
        return pid_ns;

    // If pid equals 1 - start tracing the container
    if (get_task_ns_pid(task) == 1) {
        // A new container/pod was started - add pid namespace to map
        bpf_map_update_elem(&containers_map, &pid_ns, &pid_ns, BPF_ANY);
        return pid_ns;
    }

    // Not a container/pod
    return 0;
}

static __always_inline void remove_pid() {
    u32 pid = bpf_get_current_pid_tgid();
    if (bpf_map_lookup_elem(&containers_map, &pid)) {
        bpf_map_delete_elem(&containers_map, &pid);
    }
}

static __always_inline void remove_container_pid_ns() {
    struct task_struct* task;
    task = (struct task_struct*)bpf_get_current_task();

    u32 pid_ns = get_task_pid_ns_id(task);
    if (bpf_map_lookup_elem(&containers_map, &pid_ns) != 0) {
        // If pid equals 1 - stop tracing this pid namespace
        if (get_task_ns_pid(task) == 1) {
            bpf_map_delete_elem(&containers_map, &pid_ns);
        }
    }
}

static __always_inline int should_trace() {
    // struct task_struct* task = (struct task_struct*)bpf_get_current_task();
    // u32 host_pid = bpf_get_current_pid_tgid() >> 32;

    context_t context = {};
    init_context(&context);
    
    // 不跟踪自己
    if (get_config(CONFIG_TRACEE_PID) == context.host_pid) {
        return 0;
    }

    //trace existed containers or new containers
    u32 cgroup_id_lsb = context.cgroup_id;
    if (bpf_map_lookup_elem(&existed_containers_map, &cgroup_id_lsb) == 0 &&
        bpf_map_lookup_elem(&containers_map, &context.pid_id) == 0) {
        return 0;
    }

    if (!equality_filter_matches(CONFIG_COMM_FILTER, &comm_filter, &context.comm)) {
        return 0;
    }

    return 1;
}

static __always_inline int trace_ret_generic(void* ctx, u32 id, u64 types, u64 tags, struct args_t* args, long ret) {
    buf_t* submit_p = get_buf(SUBMIT_BUF_IDX);
    if (submit_p == NULL)
        return 0;
    set_buf_off(SUBMIT_BUF_IDX, sizeof(context_t));
    u8 argnum = save_args_to_buf(types, tags, args);
    init_and_save_context(ctx, submit_p, id, argnum, ret);
    events_perf_submit(ctx);
    return 0;
}


#define TRACE_ENT_FUNC(name, id)                                        \
int trace_##name(void *ctx)                                             \
{                                                                       \
    if (!should_trace())                                                \
        return 0;                                                       \
    return save_args_from_regs(ctx, id, false);                         \
}

#define TRACE_RET_FUNC(name, id, types, tags, ret)                      \
int trace_ret_##name(void *ctx)                                         \
{                                                                       \
    args_t args = {};                                                   \
                                                                        \
    bool delete_args = true;                                            \
    if (load_args(&args, delete_args, id) != 0)                         \
        return -1;                                                      \
                                                                        \
    if (!should_trace())                                                \
        return -1;                                                      \
                                                                        \
    if (!event_chosen(id))                                              \
        return 0;                                                       \
                                                                        \
    return trace_ret_generic(ctx, id, types, tags, &args, ret);         \
}



/*============================== SYSCALL HOOKS ===============================*/
#ifndef CONFIG_ARCH_HAS_SYSCALL_WRAPPER
        #define CONFIG_ARCH_HAS_SYSCALL_WRAPPER 0
    #endif
/** struct bpf_raw_tracepoint_args *ctx; args[0] is struct pt_regs *regs and
 * args[1] is long id. struct pt_regs is a copy of the CPU registers at the
 * time sys_enter was called. id is the ID of the syscall.
 **/
 // TODO sys_enter
SEC("raw_tracepoint/sys_enter")
int tracepoint__raw_syscalls__sys_enter(struct bpf_raw_tracepoint_args* ctx) {
    

    struct args_t args_tmp = {};
    struct task_struct* task = (struct task_struct*)bpf_get_current_task();
    int id = ctx->args[1];
    
#if defined(CONFIG_ARCH_HAS_SYSCALL_WRAPPER)
    struct pt_regs* regs = (struct pt_regs*)ctx->args[0];

    if (is_x86_compat(task)) {
        #if defined (bpf_target_x86)
                args_tmp.args[0] = READ_KERN(regs->bx);
                args_tmp.args[1] = READ_KERN(regs->cx);
                args_tmp.args[2] = READ_KERN(regs->dx);
                args_tmp.args[3] = READ_KERN(regs->si);
                args_tmp.args[4] = READ_KERN(regs->di);
                args_tmp.args[5] = READ_KERN(regs->bp);
        #endif // bpf_target_x86
    }
    else {
        args_tmp.args[0] = READ_KERN(PT_REGS_PARM1(regs));
        args_tmp.args[1] = READ_KERN(PT_REGS_PARM2(regs));
        args_tmp.args[2] = READ_KERN(PT_REGS_PARM3(regs));
        #if defined(bpf_target_x86)
        // x86-64: r10 used instead of rcx (4th param to a syscall)
        args_tmp.args[3] = READ_KERN(regs->r10);
        #else
        args_tmp.args[3] = READ_KERN(PT_REGS_PARM4(regs));
        #endif
        args_tmp.args[4] = READ_KERN(PT_REGS_PARM5(regs));
        args_tmp.args[5] = READ_KERN(PT_REGS_PARM6(regs));
    }
#else // CONFIG_ARCH_HAS_SYSCALL_WRAPPER
    bpf_probe_read(args_tmp.args, sizeof(6 * sizeof(u64)), (void*)ctx->args); 
#endif // CONFIG_ARCH_HAS_SYSCALL_WRAPPER

    
    if (is_compat(task)) {
        // Translate 32bit syscalls to 64bit syscalls so we can send to the correct handler
        u32* id_64 = bpf_map_lookup_elem(&sys_32_to_64_map, &id);
        if (id_64 == 0)
            return 0;

        id = *id_64;
    }
    //u32 pid = bpf_get_current_pid_tgid();
    //execve events may add new pids to the traced pids set
    if (id == SYS_EXECVE || id == SYS_EXECVEAT) {
        add_container_pid_ns();
        // bpf_printk("raw_tracepoint_sys_exit add this container pid ns: %d to map", id);
    }
    
    if (!should_trace()) {
        return 0;
    }

    if (event_chosen(RAW_SYS_ENTER)) {
        buf_t* submit_p = get_buf(SUBMIT_BUF_IDX);
        if (submit_p == NULL) {
            return 0;
        }

        set_buf_off(SUBMIT_BUF_IDX, sizeof(context_t));
        context_t context = init_and_save_context((void*)ctx, submit_p, RAW_SYS_ENTER, 1 /*argnum*/, 0 /*ret*/);

        u64* tags = bpf_map_lookup_elem(&params_names_map, &context.eventid);
        if (!tags) {
            return -1;
        }
        save_to_buf(submit_p, (void*)&id, sizeof(int), INT_T, DEC_ARG(0, *tags));
        events_perf_submit(ctx);
    }
    // exit, exit_group and rt_sigreturn syscalls don't return - don't save args for them
    if (id != SYS_EXIT && id != SYS_EXIT_GROUP && id != SYS_RT_SIGRETURN) {
        // save the timestamp at function entry
        args_tmp.args[6] = bpf_ktime_get_ns();
        save_args(&args_tmp, id);
    }

    // call syscall handler, if exists
    // enter tail calls should never delete saved args
    bpf_tail_call(ctx, &sys_enter_tails, id);
    return 0;
}


SEC("raw_tracepoint/sys_exit")
int tracepoint__raw_syscalls__sys_exit(struct bpf_raw_tracepoint_args* ctx) {

    if (!should_trace()) {
        return 0;
    }

    long ret = ctx->args[1];;
    struct task_struct* task = (struct task_struct*)bpf_get_current_task();
    struct pt_regs* regs = (struct pt_regs*)ctx->args[0];
    int id = READ_KERN(regs->orig_ax);

    if (is_compat(task)) {
        // Translate 32bit syscalls to 64bit syscalls so we can send to the correct handler
        u32* id_64 = bpf_map_lookup_elem(&sys_32_to_64_map, &id);
        if (id_64 == 0)
            return 0;

        id = *id_64;
    }

    struct args_t saved_args = {};
    bool delete_args = true;
    if (load_args(&saved_args, delete_args, id) != 0) {
        return 0;
    }

    
    // fork events may add new pids to the traced pids set
    // perform this check after should_trace() to only add forked childs of a traced parent
    if (id == SYS_CLONE || id == SYS_FORK || id == SYS_VFORK) {
        add_container_pid_ns();
        //bpf_printk("raw_tracepoint_sys_exit add this containter pid ns id: %d to map", id);
    }
    if (event_chosen(RAW_SYS_EXIT)) {
        buf_t* submit_p = get_buf(SUBMIT_BUF_IDX);
        if (submit_p == NULL)
            return 0;
        set_buf_off(SUBMIT_BUF_IDX, sizeof(context_t));

        context_t context = init_and_save_context(ctx, submit_p, RAW_SYS_EXIT, 1 /*argnum*/, ret);

        u64* tags = bpf_map_lookup_elem(&params_names_map, &context.eventid);
        if (!tags) {
            return -1;
        }

        save_to_buf(submit_p, (void*)&id, sizeof(int), INT_T, DEC_ARG(0, *tags));
        events_perf_submit(ctx);
    }
    if (event_chosen(id)) {

        u64 types = 0;
        u64 tags = 0;
        bool submit_event = true;
        if (id != SYS_EXECVE && id != SYS_EXECVEAT) {
            u64* saved_types = bpf_map_lookup_elem(&params_types_map, &id);
            u64* saved_tags = bpf_map_lookup_elem(&params_names_map, &id);
            if (!saved_types || !saved_tags) {
                return -1;
            }
            types = *saved_types;
            tags = *saved_tags;
        }
        else {
            // We can't use saved args after execve syscall, as pointers are invalid
            // To avoid showing execve event both on entry and exit,
            // we only output failed execs
            if (ret == 0)
                submit_event = false;
        }
        if (submit_event) {
            trace_ret_generic(ctx, id, types, tags, &saved_args, ret);
        }

    }
    // call syscall handler, if exists
    // save_args(&saved_args, id);
    // save_retval(ret, id);
    // exit tail calls should always delete args and retval before return
    // bpf_tail_call(ctx, &sys_exit_tails, id);
    // del_retval(id);
    // del_args(id);
    return 0;
}

SEC("raw_tracepoint/sched_process_exit")
int tracepoint__sched__sched_process_exit(struct bpf_raw_tracepoint_args* ctx) {
    // u32 pid = bpf_get_current_pid_tgid();
    // if (!should_trace()) {
    //     return 0;
    // }

    // buf_t *submit_p = get_buf(SUBMIT_BUF_IDX);
    // if (submit_p == NULL)
    //     return 0;
    // set_buf_off(SUBMIT_BUF_IDX, sizeof(context_t));

    // init_and_save_context(ctx, submit_p, SCHED_PROCESS_EXIT, 0, 0);
    // events_perf_submit(ctx);
    return 0;
}


SEC("raw_tracepoint/sys_execve")
int syscall__execve(void* ctx) {
    struct args_t args = {};
    u8 argc = 0;

    bool delete_args = false;
    if (load_args(&args, delete_args, SYS_EXECVE) != 0) {
        return -1;
    }

    if (!event_chosen(SYS_EXECVE)) {
        return 0;
    }

    buf_t* submit_p = get_buf(SUBMIT_BUF_IDX);
    if (submit_p == NULL) {
        return 0;
    }
    set_buf_off(SUBMIT_BUF_IDX, sizeof(context_t));

    context_t context = init_and_save_context(ctx, submit_p, SYS_EXECVE, 2 /*argnum*/, 0 /*ret*/);

    u64* tags = bpf_map_lookup_elem(&params_names_map, &context.eventid);
    if (!tags) {
        return -1;
    }
    argc += save_str_to_buf(submit_p, (void*)args.args[0] /*filename*/, DEC_ARG(0, *tags));
    argc += save_str_arr_to_buf(submit_p, (const char* const*)args.args[1] /*argv*/, DEC_ARG(1, *tags));
    if (get_config(CONFIG_EXEC_ENV)) {
        argc += save_str_arr_to_buf(submit_p, (const char* const*)args.args[2] /*envp*/, DEC_ARG(2, *tags));
    }
    // bpf_printk("%s\t%s\t%s\n", args.args[0], args.args[1], args.args[2]);
    context.argc = argc;
    save_context_to_buf(submit_p, (void*)&context);
    events_perf_submit(ctx);
    return 0;
}


SEC("raw_tracepoint/sys_execveat")
int syscall__execveat(void* ctx) {
    struct args_t args = {};
    u8 argnum = 0;

    bool delete_args = false;
    if (load_args(&args, delete_args, SYS_EXECVEAT) != 0)
        return -1;

    if (!event_chosen(SYS_EXECVEAT))
        return 0;

    buf_t* submit_p = get_buf(SUBMIT_BUF_IDX);
    if (submit_p == NULL)
        return 0;
    set_buf_off(SUBMIT_BUF_IDX, sizeof(context_t));

    context_t context = init_and_save_context(ctx, submit_p, SYS_EXECVEAT, 4 /*argnum*/, 0 /*ret*/);

    u64* tags = bpf_map_lookup_elem(&params_names_map, &context.eventid);
    if (!tags) {
        return -1;
    }

    argnum += save_to_buf(submit_p, (void*)&args.args[0] /*dirfd*/, sizeof(int), INT_T, DEC_ARG(0, *tags));
    argnum += save_str_to_buf(submit_p, (void*)args.args[1] /*pathname*/, DEC_ARG(1, *tags));
    argnum += save_str_arr_to_buf(submit_p, (const char* const*)args.args[2] /*argv*/, DEC_ARG(2, *tags));
    if (get_config(CONFIG_EXEC_ENV)) {
        argnum += save_str_arr_to_buf(submit_p, (const char* const*)args.args[3] /*envp*/, DEC_ARG(3, *tags));
    }
    argnum += save_to_buf(submit_p, (void*)&args.args[4] /*flags*/, sizeof(int), INT_T, DEC_ARG(4, *tags));

    context.argc = argnum;
    save_context_to_buf(submit_p, (void*)&context);
    events_perf_submit(ctx);
    return 0;
}

// ===================vfs probes=======================
// TODO vfs辅助函数

static __always_inline struct path get_path_from_file(struct file* file) {
    return READ_KERN(file->f_path);
}

static __always_inline struct mount* real_mount(struct vfsmount* mnt) {
    return container_of(mnt, struct mount, mnt);
}

static __always_inline struct dentry* get_mnt_root_ptr_from_vfsmnt(struct vfsmount* vfsmnt) {
    return READ_KERN(vfsmnt->mnt_root);
}

static __always_inline struct dentry* get_d_parent_ptr_from_dentry(struct dentry* dentry) {
    return READ_KERN(dentry->d_parent);
}

static __always_inline struct qstr get_d_name_from_dentry(struct dentry* dentry) {
    return READ_KERN(dentry->d_name);
}

static __always_inline dev_t get_dev_from_file(struct file* file) {
    struct inode* f_inode = READ_KERN(file->f_inode);
    struct super_block* i_sb = READ_KERN(f_inode->i_sb);
    return READ_KERN(i_sb->s_dev);
}

static __always_inline unsigned long get_inode_nr_from_file(struct file* file) {
    struct inode* f_inode = READ_KERN(file->f_inode);
    return READ_KERN(f_inode->i_ino);
}

static __always_inline unsigned short get_inode_mode_from_file(struct file* file) {
    struct inode* f_inode = READ_KERN(file->f_inode);
    return READ_KERN(f_inode->i_mode);
}

static __always_inline int save_file_path_to_str_buf(buf_t* string_p, struct file* file) {
    struct path f_path = get_path_from_file(file);
    char slash = '/';
    int zero = 0;
    struct dentry* dentry = f_path.dentry;
    struct vfsmount* vfsmnt = f_path.mnt;
    struct mount* mnt_p = real_mount(vfsmnt);
    // struct mount mnt;
    // bpf_probe_read(&mnt, sizeof(struct mount), mnt_p);
    // TODO 替换为0.7.0版本的，避免结构体超出512字节，导致BPF stack放不下
    struct mount* mnt_parent_p;
    bpf_probe_read(&mnt_parent_p, sizeof(struct mount*), &mnt_p->mnt_parent);

    u32 buf_off = (MAX_PERCPU_BUFSIZE >> 1);

#pragma unroll
    // As bpf loops are not allowed and max instructions number is 4096, path components is limited to 30
    for (int i = 0; i < 30; i++) {
        struct dentry* mnt_root = get_mnt_root_ptr_from_vfsmnt(vfsmnt);
        struct dentry* d_parent = get_d_parent_ptr_from_dentry(dentry);
        if (dentry == mnt_root || dentry == d_parent) {
            if (dentry != mnt_root) {
                // We reached root, but not mount root - escaped?
                break;
            }
            // if (mnt_p != mnt.mnt_parent) {
            //     // We reached root, but not global root - continue with mount point path
            //     dentry = mnt.mnt_mountpoint;
            //     bpf_probe_read(&mnt, sizeof(struct mount), mnt.mnt_parent);
            //     vfsmnt = &mnt.mnt;
            //     continue;
            // }
            if (mnt_p != mnt_parent_p) {
                // We reached root, but not global root - continue with mount point path
                bpf_probe_read(&dentry, sizeof(struct dentry*), &mnt_p->mnt_mountpoint);
                bpf_probe_read(&mnt_p, sizeof(struct mount*), &mnt_p->mnt_parent);
                bpf_probe_read(&mnt_parent_p, sizeof(struct mount*), &mnt_p->mnt_parent);
                vfsmnt = &mnt_p->mnt;
                continue;
            }
            // Global root - path fully parsed
            break;
        }
        // Add this dentry name to path
        struct qstr d_name = get_d_name_from_dentry(dentry);
        unsigned int len = (d_name.len + 1) & (MAX_STRING_SIZE - 1);
        unsigned int off = buf_off - len;
        // Is string buffer big enough for dentry name?
        int sz = 0;
        if (off <= buf_off) { // verify no wrap occured
            len = ((len - 1) & ((MAX_PERCPU_BUFSIZE >> 1) - 1)) + 1;
            sz = bpf_probe_read_str(&(string_p->buf[off & ((MAX_PERCPU_BUFSIZE >> 1) - 1)]), len, (void*)d_name.name);
        }
        else
            break;
        if (sz > 1) {
            buf_off -= 1; // remove null byte termination with slash sign
            bpf_probe_read(&(string_p->buf[buf_off & (MAX_PERCPU_BUFSIZE - 1)]), 1, &slash);
            buf_off -= sz - 1;
        }
        else {
            // If sz is 0 or 1 we have an error (path can't be null nor an empty string)
            break;
        }
        dentry = d_parent;
    }

    if (buf_off == (MAX_PERCPU_BUFSIZE >> 1)) {
        // memfd files have no path in the filesystem -> extract their name
        buf_off = 0;
        struct qstr d_name = get_d_name_from_dentry(dentry);
        bpf_probe_read_str(&(string_p->buf[0]), MAX_STRING_SIZE, (void*)d_name.name);
    }
    else {
        // Add leading slash
        buf_off -= 1;
        bpf_probe_read(&(string_p->buf[buf_off & (MAX_PERCPU_BUFSIZE - 1)]), 1, &slash);
        // Null terminate the path string
        bpf_probe_read(&(string_p->buf[(MAX_PERCPU_BUFSIZE >> 1) - 1]), 1, &zero);
    }

    set_buf_off(STRING_BUF_IDX, buf_off);
    return buf_off;
}

static __inline int has_prefix(char* prefix, char* str, int n) {
    int i;
#pragma unroll
    for (i = 0; i < n; prefix++, str++, i++) {
        if (!*prefix)
            return 1;
        if (*prefix != *str) {
            return 0;
        }
    }

    // prefix is too long
    return 0;
}

static __always_inline int do_vfs_write_writev(struct pt_regs* ctx, u32 event_id, u32 tail_call_id) {
    args_t saved_args;
    bool has_filter = false;
    bool filter_match = false;

    bool delete_args = false;
    if (load_args(&saved_args, delete_args, event_id) != 0) {
        // missed entry or not traced
        return 0;
    }

    struct file* file = (struct file*)saved_args.args[0];

    // Get per-cpu string buffer
    buf_t* string_p = get_buf(STRING_BUF_IDX);
    if (string_p == NULL)
        return -1;
    save_file_path_to_str_buf(string_p, file);
    u32* off = get_buf_off(STRING_BUF_IDX);
    if (off == NULL)
        return -1;

    // Check if capture write was requested for this path
// #pragma unroll
//     for (int i = 0; i < 3; i++) {
//         int idx = i;
//         path_filter_t* filter_p = bpf_map_lookup_elem(&file_filter, &idx);
//         if (filter_p == NULL)
//             return -1;

//         if (!filter_p->path[0])
//             break;

//         has_filter = true;

//         if (*off > MAX_PERCPU_BUFSIZE - MAX_STRING_SIZE)
//             break;

//         if (has_prefix(filter_p->path, &string_p->buf[*off], MAX_PATH_PREF_SIZE)) {
//             filter_match = true;
//             break;
//         }
//     }

    // Submit vfs_write(v) event if it was chosen, or in case of a filter match (so we can get written_files metadata)
    if (event_chosen(VFS_WRITE) || event_chosen(VFS_WRITEV) || filter_match) {
        loff_t start_pos;
        size_t count;
        unsigned long vlen;

        buf_t* submit_p = get_buf(SUBMIT_BUF_IDX);
        if (submit_p == NULL)
            return 0;
        set_buf_off(SUBMIT_BUF_IDX, sizeof(context_t));

        init_and_save_context(ctx, submit_p, event_id, 5 /*argnum*/, PT_REGS_RC(ctx));

        if (event_id == VFS_WRITE) {
            count = (size_t)saved_args.args[2];
        }
        else {
            vlen = saved_args.args[2];
        }
        loff_t* pos = (loff_t*)saved_args.args[3];

        // Extract device id, inode number, and pos (offset)
        dev_t s_dev = get_dev_from_file(file);
        unsigned long inode_nr = get_inode_nr_from_file(file);
        bpf_probe_read(&start_pos, sizeof(off_t), pos);

        // Calculate write start offset
        if (start_pos != 0)
            start_pos -= PT_REGS_RC(ctx);

        u64* tags = bpf_map_lookup_elem(&params_names_map, &event_id);
        if (!tags) {
            return -1;
        }

        save_str_to_buf(submit_p, (void*)&string_p->buf[*off], DEC_ARG(0, *tags));
        save_to_buf(submit_p, &s_dev, sizeof(dev_t), DEV_T_T, DEC_ARG(1, *tags));
        save_to_buf(submit_p, &inode_nr, sizeof(unsigned long), ULONG_T, DEC_ARG(2, *tags));

        if (event_id == VFS_WRITE)
            save_to_buf(submit_p, &count, sizeof(size_t), SIZE_T_T, DEC_ARG(3, *tags));
        else
            save_to_buf(submit_p, &vlen, sizeof(unsigned long), ULONG_T, DEC_ARG(3, *tags));
        save_to_buf(submit_p, &start_pos, sizeof(off_t), OFF_T_T, DEC_ARG(4, *tags));

        // Submit vfs_write(v) event
        events_perf_submit(ctx);
    }

    if (has_filter && !filter_match) {
        // There is a filter, but no match
        del_args(event_id);
        return 0;
    }

    // No filter was given, or filter match - continue
    bpf_tail_call(ctx, &prog_array, tail_call_id);
    return 0;
}

static __always_inline int do_vfs_write_writev_tail(struct pt_regs* ctx, u32 event_id) {
    args_t saved_args;
    bin_args_t bin_args = {};
    loff_t start_pos;

    void* ptr;
    size_t count;
    struct iovec* vec;
    unsigned long vlen;

    buf_t* submit_p = get_buf(SUBMIT_BUF_IDX);
    if (submit_p == NULL)
        return 0;
    set_buf_off(SUBMIT_BUF_IDX, sizeof(context_t));

    context_t context = init_and_save_context(ctx, submit_p, event_id, 5 /*argnum*/, PT_REGS_RC(ctx));

    bool delete_args = true;
    if (load_args(&saved_args, delete_args, event_id) != 0) {
        // missed entry or not traced
        return 0;
    }

    struct file* file = (struct file*)saved_args.args[0];
    if (event_id == VFS_WRITE) {
        ptr = (void*)saved_args.args[1];
        count = (size_t)saved_args.args[2];
    }
    else {
        vec = (struct iovec*)saved_args.args[1];
        vlen = saved_args.args[2];
    }
    loff_t* pos = (loff_t*)saved_args.args[3];

    // Get per-cpu string buffer
    buf_t* string_p = get_buf(STRING_BUF_IDX);
    if (string_p == NULL)
        return -1;
    save_file_path_to_str_buf(string_p, file);
    u32* off = get_buf_off(STRING_BUF_IDX);
    if (off == NULL)
        return -1;

    // Extract device id, inode number, mode, and pos (offset)
    dev_t s_dev = get_dev_from_file(file);
    unsigned long inode_nr = get_inode_nr_from_file(file);
    unsigned short i_mode = get_inode_mode_from_file(file);
    bpf_probe_read(&start_pos, sizeof(off_t), pos);

    // Calculate write start offset
    if (start_pos != 0)
        start_pos -= PT_REGS_RC(ctx);

    u64 id = bpf_get_current_pid_tgid();
    u32 pid = context.pid;

    int idx = DEV_NULL_STR;
    // path_filter_t* stored_str_p = bpf_map_lookup_elem(&string_store, &idx);
    // if (stored_str_p == NULL)
    //     return -1;

    if (*off > MAX_PERCPU_BUFSIZE - MAX_STRING_SIZE)
        return -1;

    // check for /dev/null
    if (!has_prefix("/dev/null", (char*)&string_p->buf[*off], 10))
        pid = 0;

    // if (get_config(CONFIG_CAPTURE_FILES)) {
    //     bin_args.type = SEND_VFS_WRITE;
    //     bpf_probe_read(bin_args.metadata, 4, &s_dev);
    //     bpf_probe_read(&bin_args.metadata[4], 8, &inode_nr);
    //     bpf_probe_read(&bin_args.metadata[12], 4, &i_mode);
    //     bpf_probe_read(&bin_args.metadata[16], 4, &pid);
    //     bin_args.start_off = start_pos;
    //     if (event_id == VFS_WRITE) {
    //         bin_args.ptr = ptr;
    //         bin_args.full_size = PT_REGS_RC(ctx);
    //     }
    //     else {
    //         bin_args.vec = vec;
    //         bin_args.iov_idx = 0;
    //         bin_args.iov_len = vlen;
    //         if (vlen > 0) {
    //             struct iovec io_vec;
    //             bpf_probe_read(&io_vec, sizeof(struct iovec), &vec[0]);
    //             bin_args.ptr = io_vec.iov_base;
    //             bin_args.full_size = io_vec.iov_len;
    //         }
    //     }
    //     bpf_map_update_elem(&bin_args_map, &id, &bin_args, BPF_ANY);

    //     // Send file data
    //     bpf_tail_call(ctx, &prog_array, TAIL_SEND_BIN);
    // }
    bpf_tail_call(ctx, &prog_array, TAIL_SEND_BIN);
    return 0;
}


SEC("kprobe/vfs_write")
TRACE_ENT_FUNC(vfs_write, VFS_WRITE);

SEC("kretprobe/vfs_write")
int BPF_KPROBE(trace_ret_vfs_write) {
    return do_vfs_write_writev(ctx, VFS_WRITE, TAIL_VFS_WRITE);
}

SEC("kretprobe/vfs_write_tail")
int BPF_KPROBE(trace_ret_vfs_write_tail) {
    return do_vfs_write_writev_tail(ctx, VFS_WRITE);
}

SEC("kprobe/vfs_writev")
TRACE_ENT_FUNC(vfs_writev, VFS_WRITEV);

SEC("kretprobe/vfs_writev")
int BPF_KPROBE(trace_ret_vfs_writev) {
    return do_vfs_write_writev(ctx, VFS_WRITEV, TAIL_VFS_WRITEV);
}

SEC("kretprobe/vfs_writev_tail")
int BPF_KPROBE(trace_ret_vfs_writev_tail) {
    return do_vfs_write_writev_tail(ctx, VFS_WRITEV);
}



char LICENSE[] SEC("license") = "GPL";