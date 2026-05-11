// License: GPL-2.0
/*
 * Generic ftrace-based kernel function blocker.
 *
 * Edit `blocklist[]` below to choose which kernel functions get
 * redirected to a stub returning -EPERM. The redirect is done by
 * arming a single ftrace_ops (FTRACE_OPS_FL_IPMODIFY) over all listed
 * symbols and rewriting %rip at the fentry site to point at the stub.
 *
 * ftrace resolves names against whatever is currently loaded
 * (vmlinux + already-insmod'd modules). Symbols belonging to modules
 * that load LATER are not patched — load this module after them.
 *
 * Requires: CONFIG_DYNAMIC_FTRACE=y, CONFIG_FUNCTION_TRACER=y.
 * Tested against kernels 5.11+ where ftrace_regs is available.
 *
 * Stub limitations (same reasoning as livepatch-filter.c):
 *   - Targets must return int or long. -EPERM is placed in %rax,
 *     fully sign-extended.
 *   - Targets returning pointers, structs by value, or floats are NOT
 *     supported.
 *   - Arguments are ignored: on x86_64 SysV the callee never touches
 *     %rdi..%r9 or stack args it doesn't declare, and the caller is
 *     responsible for stack cleanup.
 *   - Only one ftrace_ops with IPMODIFY may be attached to a given
 *     function at a time. If another subsystem (e.g. an active
 *     livepatch) already owns the symbol, register_ftrace_function()
 *     will fail with -EBUSY.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/ftrace.h>
#include <linux/errno.h>
#include <linux/string.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Marian Marinov");
MODULE_DESCRIPTION("Block a list of kernel functions with -EPERM via ftrace");
MODULE_VERSION("0.2");

// List of functions to be blocked
static const char * const blocklist[] = {
	"af_alg_sendmsg",
	"af_alg_bind",
};

#define BLOCKLIST_LEN ARRAY_SIZE(blocklist)

/*
 * Shared replacement. Declared as returning `long` so the compiler
 * emits a full 64-bit move into %rax (sign-extending -EPERM); callers
 * expecting `int` only read %eax, which still holds -EPERM correctly.
 */
static long notrace eperm_stub(void)
{
	return -EPERM;
}

static struct ftrace_ops filter_ops __read_mostly;

static void notrace filter_thunk(unsigned long ip,
				 unsigned long parent_ip,
				 struct ftrace_ops *ops,
				 struct ftrace_regs *fregs)
{
	struct pt_regs *regs = ftrace_get_regs(fregs);

	if (unlikely(!regs))
		return;

	/*
	 * Recursion guard: if the stub itself somehow ended up calling a
	 * traced function, don't redirect again. Our stub doesn't, but
	 * this is a cheap belt-and-braces.
	 */
	if (within_module((unsigned long)parent_ip, THIS_MODULE))
		return;

	regs->ip = (unsigned long)eperm_stub;
}

static int __init filter_init(void)
{
	int ret;
	size_t i;
	size_t n_added = 0;

	if (BLOCKLIST_LEN == 0) {
		pr_err("ftrace-filter: blocklist is empty\n");
		return -EINVAL;
	}

	filter_ops.func  = filter_thunk;
	filter_ops.flags = FTRACE_OPS_FL_SAVE_REGS |
			   FTRACE_OPS_FL_IPMODIFY;

	/*
	 * reset=0 -> accumulate filters under one ftrace_ops, so all
	 * listed symbols share the same thunk + stub.
	 */
	for (i = 0; i < BLOCKLIST_LEN; i++) {
		ret = ftrace_set_filter(&filter_ops,
					(unsigned char *)blocklist[i],
					strlen(blocklist[i]), 0);
		if (ret) {
			pr_warn("ftrace-filter: ftrace_set_filter(\"%s\") failed: %d (skipping)\n",
				blocklist[i], ret);
			continue;
		}
		n_added++;
	}

	if (n_added == 0) {
		pr_err("ftrace-filter: no symbols could be filtered, aborting\n");
		ftrace_set_filter(&filter_ops, NULL, 0, 1);
		return -ENOENT;
	}

	ret = register_ftrace_function(&filter_ops);
	if (ret) {
		pr_err("ftrace-filter: register_ftrace_function failed: %d\n",
		       ret);
		ftrace_set_filter(&filter_ops, NULL, 0, 1);
		return ret;
	}

	pr_info("ftrace-filter: %zu/%zu function(s) now return -EPERM\n",
		n_added, BLOCKLIST_LEN);
	return 0;
}

static void __exit filter_exit(void)
{
	unregister_ftrace_function(&filter_ops);
	ftrace_set_filter(&filter_ops, NULL, 0, 1);
	pr_info("ftrace-filter: unloaded\n");
}

module_init(filter_init);
module_exit(filter_exit);
