# kernel-filter

Two Linux kernel modules that force a configurable list of in-kernel
functions to return `-EPERM` on every call. Useful for ad-hoc kernel-side
mitigations: disabling a syscall path that has an open CVE, blocking
kernel functionality without rebuilding the kernel, neutering a problematic 
driver entry point, etc.

The same blocklist concept is implemented two ways:

| File | Mechanism | When to prefer |
|---|---|---|
| `block-functions.c` | dynamic ftrace + `FTRACE_OPS_FL_IPMODIFY` | quick, no special kernel config beyond `DYNAMIC_FTRACE` |
| `livepatch-filter.c` | kernel livepatching (`klp_enable_patch`) | safer transition semantics, patches modules loaded later, requires `CONFIG_LIVEPATCH=y` |

Both load the same kind of stub: a single `eperm_stub` shared across all
listed functions, which returns `-EPERM` regardless of the caller's
arguments.

## Requirements

Common:
- x86_64 (the stub relies on SysV register ABI for return-value handling)
- Kernel headers / build tree at `/lib/modules/$(uname -r)/build`
- Kernel 5.11 or newer (for the `ftrace_regs` API used by both modules)

ftrace module (`block-functions.c`):
- `CONFIG_DYNAMIC_FTRACE=y`
- `CONFIG_FUNCTION_TRACER=y`

Livepatch module (`livepatch-filter.c`):
- `CONFIG_LIVEPATCH=y` (implies `DYNAMIC_FTRACE_WITH_REGS=y` and
  `HAVE_RELIABLE_STACKTRACE=y`)

Most stock distro kernels (Debian, Ubuntu, Fedora, RHEL) ship with all
of these enabled.

## Configuring the blocklist

### ftrace version — `block-functions.c`

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

### Livepatch version — `livepatch-filter.c`

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

Produces `block-functions.ko` and `livepatch-filter.ko`. Override the
target kernel with `KDIR=/path/to/build` if needed.

## Load / unload

The Makefile has convenience targets. The kernel normalizes `-` to `_`
in module names, so `block-functions.ko` registers as `block_functions`
and `livepatch-filter.ko` as `livepatch_filter`.

### ftrace

```sh
make load-ftrace      # insmod block-functions.ko
make unload-ftrace    # rmmod block_functions
```

Removal is immediate.

### Livepatch

```sh
make load-livepatch   # insmod livepatch-filter.ko
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

## Conflicts between the two modules

Both modules ultimately install an `FTRACE_OPS_FL_IPMODIFY` hook on
their target symbols, and only one such hook per function is allowed.
If you have an active livepatch on `af_alg_sendmsg` and then try to
load `block-functions.ko` with `af_alg_sendmsg` in its blocklist,
`register_ftrace_function()` will fail with `-EBUSY`. Pick one
mechanism per symbol.

## Persistence

Nothing here is persistent. To survive reboot, install the `.ko` under
`/lib/modules/$(uname -r)/extra/`, run `depmod -a`, and add the module
name to `/etc/modules-load.d/`.

## Files

```
block-functions.c    ftrace-based blocker, edit blocklist[] at top
livepatch-filter.c   livepatch-based blocker, edit blocklist[] at top
Makefile             kbuild + load/unload helpers
README.md            this file
```

## License

GPL-2.0
