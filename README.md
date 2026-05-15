# kernel-filter

A small collection of Linux kernel modules for ad-hoc, runtime kernel
mitigations: disabling syscall paths with open CVEs, blocking subsystems
without rebuilding the kernel, or back-porting an upstream security fix
in-place.

Two flavours of each: an **ftrace** version (low-config) and a
**livepatch** version (cleaner consistency model, can target
not-yet-loaded modules).

| File | Mechanism | Purpose |
|---|---|---|
| `filter-functions-ftrace.c` | dynamic ftrace + `IPMODIFY` | generic: replace a configurable list of functions with `-EPERM` |
| `filter-functions-livepatch.c` | livepatching | same, but via livepatch |
| `ptrace-fix-ftrace.c` | dynamic ftrace + `IPMODIFY` | targeted: mitigate the ptrace-after-exit_mm bypass (upstream commit `31e62c2ebbfd`, "ssh-keysign" chain) |
| `ptrace-fix-livepatch.c` | livepatching | same mitigation, via livepatch |

The generic blockers (`filter-functions-ftrace.c` / `filter-functions-livepatch.c`) share a
single `eperm_stub` that returns `-EPERM` regardless of arguments. The
ptrace mitigations are more surgical — they only force `-EPERM` under
specific runtime conditions; otherwise the original function runs.

## Requirements

Common:
- x86_64 (callbacks read `%rdi`/`%rsi` and the stub relies on SysV
  register ABI for return-value handling)
- Kernel headers / build tree at `/lib/modules/$(uname -r)/build`
- Kernel 4.11 or newer (each source file selects the right API at compile
  time via `LINUX_VERSION_CODE`; `ftrace_regs` on >=5.11, `klp_register_patch`
  on <5.1)

ftrace modules:
- `CONFIG_DYNAMIC_FTRACE=y`
- `CONFIG_FUNCTION_TRACER=y`
- `CONFIG_DYNAMIC_FTRACE_WITH_REGS=y`

Livepatch modules:
- `CONFIG_LIVEPATCH=y` (implies `DYNAMIC_FTRACE_WITH_REGS=y` and
  `HAVE_RELIABLE_STACKTRACE=y`)
- `CONFIG_KPROBES=y` (the ptrace livepatch uses a kprobe to resolve
  `kallsyms_lookup_name` on >=5.7)

Most stock distro kernels (Debian, Ubuntu, Fedora, RHEL) ship with all
of these enabled.

## Configuring the blocklist

### ftrace version — `filter-functions-ftrace.c`

Edit the array near the top of the file. Each entry is a symbol name as
it appears in `/proc/kallsyms`:

```c
static const char * const blocklist[] = {
    "af_alg_sendmsg",
    "af_alg_bind",
};
```

ftrace resolves names against whatever is currently loaded (vmlinux plus
already-`insmod`'d modules). Symbols that belong to modules loaded
*after* this one are not patched.

### Livepatch version — `filter-functions-livepatch.c`

Edit the array near the top of the file. Each entry is `{module_name,
function_name}`. `module_name == NULL` means the symbol lives in
vmlinux:

```c
static const struct blocked_func blocklist[] = {
    { "af_alg", "af_alg_sendmsg" },
    { "af_alg", "af_alg_bind"    },
    /* { NULL, "some_vmlinux_function" }, */
};
```

Livepatch will apply a pending patch to a module when that module is
loaded later, so `{ "af_alg", ... }` works whether `af_alg.ko` is
already loaded or not.

## Build

```sh
make
```

Produces `filter-functions-ftrace.ko` and `filter-functions-livepatch.ko`. Override the
target kernel with `KDIR=/path/to/build` if needed.

## Load / unload

The Makefile has convenience targets. The kernel normalizes `-` to `_`
in module names, so `filter-functions-ftrace.ko` registers as `block_functions`
and `filter-functions-livepatch.ko` as `livepatch_filter`.

### ftrace

```sh
make load-ftrace      # insmod filter-functions-ftrace.ko
make unload-ftrace    # rmmod block_functions
```

Removal is immediate.

### Livepatch

```sh
make load-livepatch   # insmod filter-functions-livepatch.ko
make unload-livepatch # disable via sysfs, wait for transition, rmmod
```

A livepatch module cannot be removed while the patch is enabled. The
`unload-livepatch` target handles the dance:

```
echo 0 > /sys/kernel/livepatch/livepatch_filter/enabled
# poll /sys/kernel/livepatch/livepatch_filter/transition until "0"
rmmod livepatch_filter
```

If a task is wedged inside a patched function and the transition never
completes, you can force it (taints the kernel):

```sh
echo 1 | sudo tee /sys/kernel/livepatch/livepatch_filter/force
```

## What the stub can and cannot replace

`eperm_stub` is declared `static long notrace eperm_stub(void) { return -EPERM; }`.
On x86_64 SysV:

- **Return value.** The compiler emits a full 64-bit move into `%rax`,
  so `-EPERM` is sign-extended. Callers reading `int` see it in `%eax`;
  callers reading `long` see it in `%rax`. Both work.
- **Arguments.** The callee never touches `%rdi`..`%r9` or stack args
  it doesn't declare, and the caller cleans up the stack. So any
  argument list is safe — the stub doesn't need to match the original
  signature.

Supported target signatures: anything returning `int`, `long`,
`ssize_t`, or another register-sized integer.

**Not supported:**
- Functions returning pointers, struct-by-value, or floating point
- Functions tail-called via `noreturn` paths
- Architectures other than x86_64 (the same idea works on arm64 / etc.
  but the stub-return reasoning needs revisiting per ABI)

## Conflicts between the two mechanisms

All four modules ultimately install an `FTRACE_OPS_FL_IPMODIFY` hook on
their target symbols, and only one such hook per function is allowed.
If you have an active livepatch on a function and then try to load an
ftrace module that touches it, `register_ftrace_function()` will fail
with `-EBUSY`. In particular, do not load both ptrace mitigations at
once.

## ptrace exit_mm() dumpability mitigation

`ptrace-fix-ftrace.c` and `ptrace-fix-livepatch.c` back-port a
mitigation for the bug fixed upstream by commit
[`31e62c2ebbfd`](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=31e62c2ebbfdc3fe3dbdf5e02c92a9dc67087a3a)
("ptrace: slightly saner 'get_dumpable()' logic"). The original bug:
`__ptrace_may_access()` did

```c
mm = task->mm;
if (mm && ((get_dumpable(mm) != SUID_DUMP_USER) &&
           !ptrace_has_cap(mm->user_ns, mode)))
    return -EPERM;
```

so a target whose `mm` had been torn down by `exit_mm()` silently
**skipped** the dumpability check — letting an unprivileged tracer
attach to a previously-non-dumpable exiting task (the Qualys
ssh-keysign chain).

Upstream caches the pre-exit dumpable state in a new
`task->user_dumpable:1` bit. **Neither ftrace nor livepatch can extend
`struct task_struct`**, so these modules apply a stricter mitigation:

> When `task->mm == NULL` and the tracer is not in the same thread
> group as the target, require `CAP_SYS_PTRACE` in `init_user_ns`.

This matches upstream exactly for kernel threads and for tasks that
were never dumpable. It is **stricter than upstream** in one narrow
case: a userspace task whose `mm` has just been torn down and that
*was* originally `SUID_DUMP_USER` is no longer ptrace-able by its
non-privileged tracer. Acceptable for a backport; verify in your
environment before relying on it.

Load:

```sh
make load-ptrace-ftrace       # or load-ptrace-livepatch
```

Verify the ftrace version found its target:

```sh
grep ' __ptrace_may_access$' /proc/kallsyms
dmesg | tail
```

If `__ptrace_may_access` is inlined in your kernel, the ftrace version
will fail to attach — use the livepatch version, which hooks the public
`ptrace_may_access` instead and delegates internally.

## Persistence

Nothing here is persistent. To survive reboot, install the `.ko` under
`/lib/modules/$(uname -r)/extra/`, run `depmod -a`, and add the module
name to `/etc/modules-load.d/`.

## Files

```
filter-functions-ftrace.c        generic ftrace blocker, edit blocklist[] at top
filter-functions-livepatch.c       generic livepatch blocker, edit blocklist[] at top
ptrace-fix-ftrace.c      mitigation for commit 31e62c2ebbfd via ftrace
ptrace-fix-livepatch.c   mitigation for commit 31e62c2ebbfd via livepatch
Makefile                 kbuild + load/unload helpers
README.md                this file
```

## License

GPL-2.0.
