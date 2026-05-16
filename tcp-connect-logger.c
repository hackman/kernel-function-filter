// License: GPL-2.0
/*
 * tcp-connect-logger: livepatch tutorial example.
 *
 * Replaces tcp_v4_connect() with a wrapper that, when enabled, logs
 * destination IP/port plus the caller's pid/comm, then delegates to
 * the original implementation. A sysfs flag at
 *
 *   /sys/kernel/tcp_connect_logger/enabled
 *
 * gates the logging. Logging is OFF at load time; the wrapper is
 * always installed (the flag check is the only runtime difference).
 *
 * Walked through step by step in LIVEPATCH.md.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/livepatch.h>
#include <linux/kallsyms.h>
#include <linux/kobject.h>
#include <linux/sysfs.h>
#include <linux/version.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <linux/sched.h>
#include <linux/cred.h>
#include <linux/uidgid.h>
#include <linux/user_namespace.h>
#include <linux/errno.h>
#include <net/sock.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0)
# include <linux/kprobes.h>
# define NEED_KPROBE_FALLBACK 1
#endif

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Marian Marinov");
MODULE_DESCRIPTION("Livepatch tutorial: log tcp_v4_connect with sysfs toggle");
MODULE_INFO(livepatch, "Y");

// 1. kallsyms lookup
typedef unsigned long (*kln_t)(const char *);

static kln_t resolve_kln(void)
{
#ifdef NEED_KPROBE_FALLBACK
	struct kprobe kp = { .symbol_name = "kallsyms_lookup_name" };
	kln_t fn;
	int ret = register_kprobe(&kp);
	if (ret < 0) {
		pr_err("tcp_connect_logger: register_kprobe failed: %d\n", ret);
		return NULL;
	}
	fn = (kln_t)kp.addr;
	unregister_kprobe(&kp);
	return fn;
#else
	return (kln_t)kallsyms_lookup_name;
#endif
}

// 2. original-function pointer & toggle
static int (*orig_tcp_v4_connect)(struct sock *sk,
				  struct sockaddr *uaddr,
				  int addr_len);

/*
 * Plain int read with READ_ONCE on the hot path is sufficient: the
 * worst race is a logged-vs-not-logged decision being one step stale.
 */
static int logging_enabled;

// 3. the replacement
static int patched_tcp_v4_connect(struct sock *sk,
				  struct sockaddr *uaddr,
				  int addr_len)
{
	if (READ_ONCE(logging_enabled) && uaddr &&
	    addr_len >= (int)sizeof(struct sockaddr_in)) {
		struct sockaddr_in *sin = (struct sockaddr_in *)uaddr;
		if (sin->sin_family == AF_INET) {
			pr_info("tcp_connect_logger: pid=%d uid=%u comm=%s -> %pI4:%u\n",
				current->pid,
				from_kuid(&init_user_ns, current_uid()),
				current->comm,
				&sin->sin_addr, ntohs(sin->sin_port));
		}
	}
	return orig_tcp_v4_connect(sk, uaddr, addr_len);
}

// 4. livepatch wiring
static struct klp_func funcs[] = {
	{
		.old_name = "tcp_v4_connect",
		.new_func = patched_tcp_v4_connect,
	},
	{ }
};

static struct klp_object objs[] = {
	{ .funcs = funcs },		// NULL name -> vmlinux
	{ }
};

static struct klp_patch patch = {
	.mod  = THIS_MODULE,
	.objs = objs,
};

// 5. sysfs control
static ssize_t enabled_show(struct kobject *kobj,
			    struct kobj_attribute *attr,
			    char *buf)
{
	return sysfs_emit(buf, "%d\n", READ_ONCE(logging_enabled));
}

static ssize_t enabled_store(struct kobject *kobj,
			     struct kobj_attribute *attr,
			     const char *buf, size_t count)
{
	int v;
	int err = kstrtoint(buf, 10, &v);
	if (err)
		return err;
	WRITE_ONCE(logging_enabled, !!v);
	return count;
}

static struct kobj_attribute enabled_attr =
	__ATTR(enabled, 0644, enabled_show, enabled_store);

static struct attribute *tcl_attrs[] = {
	&enabled_attr.attr,
	NULL,
};

static const struct attribute_group tcl_group = {
	.attrs = tcl_attrs,
};

static struct kobject *tcl_kobj;

// 6. init / exit
static int __init tcl_init(void)
{
	kln_t kln;
	unsigned long addr;
	int ret;

	kln = resolve_kln();
	if (!kln)
		return -ENOENT;

	addr = kln("tcp_v4_connect");
	if (!addr) {
		pr_err("tcp_connect_logger: tcp_v4_connect not in kallsyms\n");
		return -ENOENT;
	}
	orig_tcp_v4_connect = (typeof(orig_tcp_v4_connect))addr;

	tcl_kobj = kobject_create_and_add("tcp_connect_logger", kernel_kobj);
	if (!tcl_kobj)
		return -ENOMEM;

	ret = sysfs_create_group(tcl_kobj, &tcl_group);
	if (ret) {
		kobject_put(tcl_kobj);
		return ret;
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 1, 0)
	ret = klp_enable_patch(&patch);
#else
	ret = klp_register_patch(&patch);
	if (!ret) {
		ret = klp_enable_patch(&patch);
		if (ret)
			klp_unregister_patch(&patch);
	}
#endif
	if (ret) {
		pr_err("tcp_connect_logger: klp_enable_patch failed: %d\n", ret);
		sysfs_remove_group(tcl_kobj, &tcl_group);
		kobject_put(tcl_kobj);
		return ret;
	}

	pr_info("tcp_connect_logger: loaded, logging disabled\n");
	pr_info("tcp_connect_logger: enable with: "
		"echo 1 > /sys/kernel/tcp_connect_logger/enabled\n");
	return 0;
}

static void __exit tcl_exit(void)
{
	sysfs_remove_group(tcl_kobj, &tcl_group);
	kobject_put(tcl_kobj);

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 1, 0)
	klp_disable_patch(&patch);
	klp_unregister_patch(&patch);
#endif
	/*
	 * On >= 5.1 the patch must be disabled via sysfs *before* rmmod:
	 *   echo 0 > /sys/kernel/livepatch/tcp_connect_logger/enabled
	 * then wait for .../transition to read 0, then rmmod.
	 */
}

module_init(tcl_init);
module_exit(tcl_exit);
