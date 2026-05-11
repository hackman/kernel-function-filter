// License: GPL-2.0
/*
 * Generic livepatch-based syscall/function blocker.
 *
 * Edit `blocklist[]` below to choose which kernel functions get replaced
 * with a stub returning -EPERM. Each entry is {module_name, func_name}:
 *   - module_name == NULL  -> symbol lives in vmlinux
 *   - module_name != NULL  -> symbol lives in that loadable module
 *
 * At init time we walk the blocklist, group entries by their target
 * object (vmlinux or named module), and build the klp_object / klp_func
 * arrays the livepatch core expects.
 *
 * Limitations of the shared stub (`eperm_stub`):
 *   - Targets must return `int` or `long` (any integer that fits in a
 *     register). -EPERM is placed in %rax, fully sign-extended.
 *   - Targets returning pointers, structs by value, or floats are NOT
 *     supported.
 *   - Arguments are ignored. On x86_64 SysV the callee never touches
 *     %rdi..%r9 or stack args, and the caller is responsible for stack
 *     cleanup, so any argument list is safe.
 *
 * Requires CONFIG_LIVEPATCH=y.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/livepatch.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/errno.h>

struct blocked_func {
	const char *mod;	/* NULL => vmlinux */
	const char *func;
};

// List of functions to be blocked
static const struct blocked_func blocklist[] = {
	{ "af_alg", "af_alg_sendmsg" },
	{ "af_alg", "af_alg_bind"    },
	/* { NULL,    "some_vmlinux_function" }, */
};

#define BLOCKLIST_LEN ARRAY_SIZE(blocklist)

/*
 * Shared replacement. Declared as returning `long` so the compiler emits
 * a full 64-bit move into %rax (sign-extending -EPERM); callers expecting
 * `int` only read %eax, which still holds -EPERM correctly.
 */
static long notrace eperm_stub(void)
{
	return -EPERM;
}

// Tables built at init from `blocklist`, freed at exit.
static struct klp_object *objs;
static struct klp_patch   patch;

static bool same_obj(const char *a, const char *b)
{
	if (!a && !b)
		return true;
	if (!a || !b)
		return false;
	return strcmp(a, b) == 0;
}

static void free_tables(void)
{
	size_t i;

	if (!objs)
		return;
	for (i = 0; objs[i].funcs; i++)
		kfree(objs[i].funcs);
	kfree(objs);
	objs = NULL;
}

static int build_tables(void)
{
	// These are fixed-size (BLOCKLIST_LEN is a compile-time constant).
	const char *seen[BLOCKLIST_LEN];
	size_t      counts[BLOCKLIST_LEN] = { 0 };
	size_t      idx[BLOCKLIST_LEN]    = { 0 };
	size_t      n_objs = 0;
	size_t      i, j;

	if (BLOCKLIST_LEN == 0) {
		pr_err("eperm_livepatch: blocklist is empty\n");
		return -EINVAL;
	}

	// Pass 1: group blocklist entries by target object.
	for (i = 0; i < BLOCKLIST_LEN; i++) {
		bool found = false;
		for (j = 0; j < n_objs; j++) {
			if (same_obj(seen[j], blocklist[i].mod)) {
				counts[j]++;
				found = true;
				break;
			}
		}
		if (!found) {
			seen[n_objs]   = blocklist[i].mod;
			counts[n_objs] = 1;
			n_objs++;
		}
	}

	// +1 zero-terminator entry.
	objs = kcalloc(n_objs + 1, sizeof(*objs), GFP_KERNEL);
	if (!objs)
		return -ENOMEM;

	for (i = 0; i < n_objs; i++) {
		struct klp_func *f = kcalloc(counts[i] + 1, sizeof(*f),
					     GFP_KERNEL);
		if (!f) {
			free_tables();
			return -ENOMEM;
		}
		objs[i].name  = seen[i];	// may be NULL for vmlinux
		objs[i].funcs = f;
	}

	// Pass 2: populate funcs in the right object's array.
	for (i = 0; i < BLOCKLIST_LEN; i++) {
		for (j = 0; j < n_objs; j++) {
			if (same_obj(seen[j], blocklist[i].mod)) {
				struct klp_func *f =
					&objs[j].funcs[idx[j]++];
				f->old_name = blocklist[i].func;
				f->new_func = (void *)eperm_stub;
				break;
			}
		}
	}

	return 0;
}

static int __init eperm_livepatch_init(void)
{
	int ret;

	ret = build_tables();
	if (ret)
		return ret;

	patch.mod  = THIS_MODULE;
	patch.objs = objs;

	ret = klp_enable_patch(&patch);
	if (ret) {
		pr_err("eperm_livepatch: klp_enable_patch failed: %d\n", ret);
		free_tables();
		return ret;
	}

	pr_info("eperm_livepatch: %zu function(s) now return -EPERM\n",
		BLOCKLIST_LEN);
	return 0;
}

static void __exit eperm_livepatch_exit(void)
{
	/*
	 * Reached only after the patch has been disabled via sysfs:
	 *   echo 0 > /sys/kernel/livepatch/eperm_livepatch/enabled
	 *   (wait for .../transition to read 0)
	 *   rmmod eperm_livepatch
	 */
	free_tables();
}

module_init(eperm_livepatch_init);
module_exit(eperm_livepatch_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Marian Marinov");
MODULE_DESCRIPTION("Livepatch: replace a configurable set of kernel functions with -EPERM");
MODULE_INFO(livepatch, "Y");
