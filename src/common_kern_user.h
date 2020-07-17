/* A common place to definea shared struct between kernel and userspace */

#ifndef __COMMON_KERN_USER_H
#define __COMMON_KERN_USER_H

/* source and destination as the maps key */
struct key_addr {
	__u64 saddr;
	__u64 daddr;
};

#ifndef XDP_ACTION_MAX
#define XDP_ACTION_MAX (XDP_REDIRECT + 1)
#endif

#endif /* __COMMON_KERN_USER_H */
