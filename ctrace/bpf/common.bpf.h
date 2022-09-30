#ifndef __COMMON_H__
#define __COMMON_H__

#include <linux/version.h>

#define READ_KERN(ptr)                                                  \
    ({                                                                  \
        typeof(ptr) _val;                                               \
        __builtin_memset((void *)&_val, 0, sizeof(_val));               \
        bpf_core_read((void *)&_val, sizeof(_val), &ptr);               \
        _val;                                                           \
    })

#define READ_USER(ptr)                                                  \
    ({                                                                  \
        typeof(ptr) _val;                                               \
        __builtin_memset((void *)&_val, 0, sizeof(_val));               \
        bpf_core_read_user((void *)&_val, sizeof(_val), &ptr);          \
        _val;                                                           \
    })

#define BPF_MAP(_name, _type, _key_type, _value_type, _max_entries)     \
    struct {                                                            \
        __uint(type, _type);                                            \
        __uint(max_entries, _max_entries);                              \
        __type(key, _key_type);                                         \
        __type(value, _value_type);                                     \
    } _name SEC(".maps");

#define BPF_HASH(_name, _key_type, _value_type) \
    BPF_MAP(_name, BPF_MAP_TYPE_HASH, _key_type, _value_type, 10240)

#define BPF_LRU_HASH(_name, _key_type, _value_type) \
    BPF_MAP(_name, BPF_MAP_TYPE_LRU_HASH, _key_type, _value_type, 10240)

#define BPF_ARRAY(_name, _value_type, _max_entries) \
    BPF_MAP(_name, BPF_MAP_TYPE_ARRAY, u32, _value_type, _max_entries)

#define BPF_PERCPU_ARRAY(_name, _value_type, _max_entries) \
    BPF_MAP(_name, BPF_MAP_TYPE_PERCPU_ARRAY, u32, _value_type, _max_entries)

#define BPF_PROG_ARRAY(_name, _max_entries) \
    BPF_MAP(_name, BPF_MAP_TYPE_PROG_ARRAY, u32, u32, _max_entries)

#define BPF_PERF_OUTPUT(_name) \
    struct {                                                            \
        __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);                    \
        __uint(key_size, sizeof(u32));                                  \
        __uint(value_size, sizeof(u32));                                \
    } _name SEC(".maps");

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 18, 0)
#error Minimal required kernel version is 4.18
#endif

#endif