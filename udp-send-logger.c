// License: GPL-2.0
/*
 * udp-send-logger: livepatch that logs every outgoing UDP/IPv4 datagram.
 *
 * Wraps udp_sendmsg() in net/ipv4/udp.c -- the kernel funnel for all
 * outgoing UDP/IPv4 traffic regardless of whether userspace used
 * send()/sendto()/sendmsg() or whether the socket was connect()ed.
 *
 * Sysfs toggle (default 0):
 *   /sys/kernel/udp_send_logger/enabled
 *
 * Sister module to tcp-connect-logger.c.
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
#include <linux/socket.h>
#include <linux/sched.h>
#include <linux/cred.h>
#include <linux/uidgid.h>
#include <linux/user_namespace.h>
#include <linux/errno.h>
#include <net/sock.h>
#include <net/inet_sock.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0)
# include <linux/kprobes.h>
# define NEED_KPROBE_FALLBACK 1
#endif

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Marian Marinov");
MODULE_DESCRIPTION("Livepatch: log outgoing UDP/IPv4 sends with sysfs toggle");
MODULE_INFO(livepatch, "Y");

// kallsyms lookup
typedef unsigned long (*kln_t)(const char *);

static kln_t resolve_kln(void)
{
#ifdef NEED_KPROBE_FALLBACK
	struct kprobe kp = { .symbol_name = "kallsyms_lookup_name" };
	kln_t fn;
	int ret = register_kprobe(&kp);
	if (ret < 0) {
		pr_err("udp_send_logger: register_kprobe failed: %d\n", ret);
		return NULL;
	}
	fn = (kln_t)kp.addr;
	unregister_kprobe(&kp);
	return fn;
#else
	return (kln_t)kallsyms_lookup_name;
#endif
}

// original-function pointer & toggle
static int (*orig_udp_sendmsg)(struct sock *sk,
			       struct msghdr *msg,
			       size_t len);

static int logging_enabled;	// default 0

// the replacement
static int patched_udp_sendmsg(struct sock *sk,
			       struct msghdr *msg,
			       size_t len)
{
	if (READ_ONCE(logging_enabled)) {
		__be32 daddr = 0;
		__be16 dport = 0;

		/*
		 * Destination comes from msg_name on unconnected sockets
		 * (sendto / sendmsg with explicit dest), or from the socket's
		 * stored peer address when connect()ed.
		 */
		if (msg && msg->msg_name &&
		    msg->msg_namelen >= (int)sizeof(struct sockaddr_in)) {
			struct sockaddr_in *sin =
				(struct sockaddr_in *)msg->msg_name;
			if (sin->sin_family == AF_INET) {
				daddr = sin->sin_addr.s_addr;
				dport = sin->sin_port;
			}
		} else if (sk) {
			struct inet_sock *inet = inet_sk(sk);
			daddr = inet->inet_daddr;
			dport = inet->inet_dport;
		}

		if (daddr) {
			pr_info("udp_send_logger: pid=%d uid=%u comm=%s -> %pI4:%u (len=%zu)\n",
				current->pid,
				from_kuid(&init_user_ns, current_uid()),
				current->comm,
				&daddr, ntohs(dport), len);
		}
	}
	return orig_udp_sendmsg(sk, msg, len);
}

// livepatch wiring
static struct klp_func funcs[] = {
	{
		.old_name = "udp_sendmsg",
		.new_func = patched_udp_sendmsg,
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

// sysfs control
static ssize_t enabled_show(struct kobject *kobj,
			    struct kobj_attribute *attr, char *buf)
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

static struct attribute *usl_attrs[] = {
	&enabled_attr.attr,
	NULL,
};

static const struct attribute_group usl_group = {
	.attrs = usl_attrs,
};

static struct kobject *usl_kobj;

// init / exit
static int __init usl_init(void)
{
	kln_t kln;
	unsigned long addr;
	int ret;

	kln = resolve_kln();
	if (!kln)
		return -ENOENT;

	addr = kln("udp_sendmsg");
	if (!addr) {
		pr_err("udp_send_logger: udp_sendmsg not in kallsyms\n");
		return -ENOENT;
	}
	orig_udp_sendmsg = (typeof(orig_udp_sendmsg))addr;

	usl_kobj = kobject_create_and_add("udp_send_logger", kernel_kobj);
	if (!usl_kobj)
		return -ENOMEM;

	ret = sysfs_create_group(usl_kobj, &usl_group);
	if (ret) {
		kobject_put(usl_kobj);
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
		pr_err("udp_send_logger: klp_enable_patch failed: %d\n", ret);
		sysfs_remove_group(usl_kobj, &usl_group);
		kobject_put(usl_kobj);
		return ret;
	}

	pr_info("udp_send_logger: loaded, logging disabled\n");
	pr_info("udp_send_logger: enable with: "
		"echo 1 > /sys/kernel/udp_send_logger/enabled\n");
	return 0;
}

static void __exit usl_exit(void)
{
	sysfs_remove_group(usl_kobj, &usl_group);
	kobject_put(usl_kobj);

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 1, 0)
	klp_disable_patch(&patch);
	klp_unregister_patch(&patch);
#endif
	/*
	 * On >= 5.1 the patch must be disabled via sysfs *before* rmmod:
	 *   echo 0 > /sys/kernel/livepatch/udp_send_logger/enabled
	 * Wait for .../transition to read 0, then rmmod.
	 */
}

module_init(usl_init);
module_exit(usl_exit);
