/*
 * Copyright (c) 2026, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <AK/Platform.h>
#include <LibSandbox/Sandbox.h>
#include <LibSandbox/Seccomp.h>
#include <LibTest/TestCase.h>

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

// The ImageDecoder seccomp policy allows fstat but not newfstatat. glibc builds
// that implement fstat() as newfstatat(fd, "", buf, AT_EMPTY_PATH) would trip the
// sandbox; the policy emulates that exact form as a plain fstat. These tests call
// newfstatat directly (bypassing glibc's wrapper) so the behaviour is verified on
// any host regardless of which syscall its libc happens to pick.

#if defined(AK_OS_LINUX) && defined(__NR_newfstatat)

// Mirrors Services/ImageDecoder/SandboxLinux.cpp's seccomp configuration.
static void apply_image_decoder_seccomp()
{
    MUST(Sandbox::install_no_new_privileges());

    Sandbox::SeccompPolicy policy;
    policy.deny_readonly_filesystem_probes();
    policy.allow_file_descriptor_operations();
    policy.allow_ipc();
    policy.allow_common_runtime();
    MUST(policy.install());
}

// Runs `body` in a forked child under the ImageDecoder sandbox and returns its
// wait status, so a trapped syscall is observable without poisoning the test
// runner. A clean run exits 0; a trapped syscall exits with 128 + SIGSYS.
static int run_sandboxed(void (*body)())
{
    auto pid = fork();
    VERIFY(pid >= 0);
    if (pid == 0) {
        apply_image_decoder_seccomp();
        body();
        _exit(0);
    }
    int status = 0;
    VERIFY(waitpid(pid, &status, 0) == pid);
    return status;
}

TEST_CASE(fd_newfstatat_is_emulated_as_fstat)
{
    auto status = run_sandboxed([] {
        struct stat st = {};
        // The fstat-in-disguise form glibc emits on some builds.
        auto rc = syscall(SYS_newfstatat, STDIN_FILENO, "", &st, AT_EMPTY_PATH);
        if (rc != 0)
            _exit(42);
    });
    EXPECT(WIFEXITED(status));
    EXPECT_EQ(WEXITSTATUS(status), 0);
}

TEST_CASE(path_newfstatat_is_still_blocked)
{
    auto status = run_sandboxed([] {
        struct stat st = {};
        // A real path query must not be emulated; the sandbox should trap it.
        (void)syscall(SYS_newfstatat, AT_FDCWD, "/etc/hostname", &st, 0);
        _exit(0);
    });
    // A trapped syscall makes the SIGSYS handler exit the child with 128 + SIGSYS.
    EXPECT(WIFEXITED(status));
    EXPECT_EQ(WEXITSTATUS(status), 128 + SIGSYS);
}

#endif
