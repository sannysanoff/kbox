/* SPDX-License-Identifier: MIT */
#include <errno.h>
#include <stdint.h>
#include <sys/stat.h>
#include <unistd.h>

#include "test-runner.h"
#include "vcred.h"

#define P 910001 /* a pid nothing else uses; its /proc entry does not exist */

static void test_new_pid_is_root(void)
{
    struct kbox_vcred c;
    kbox_vcred_reset_for_test();
    kbox_vcred_get(P, &c);
    ASSERT_EQ(c.ruid, 0);
    ASSERT_EQ(c.euid, 0);
    ASSERT_EQ(c.egid, 0);
}

static void test_root_setuid_sets_all_ids(void)
{
    struct kbox_vcred c;
    kbox_vcred_reset_for_test();
    ASSERT_EQ(kbox_vcred_setuid(P, 999), 0);
    kbox_vcred_get(P, &c);
    ASSERT_EQ(c.ruid, 999);
    ASSERT_EQ(c.euid, 999);
    ASSERT_EQ(c.suid, 999);
}

static void test_nonroot_cannot_regain_root(void)
{
    kbox_vcred_reset_for_test();
    ASSERT_EQ(kbox_vcred_setgid(P, 999), 0);
    ASSERT_EQ(kbox_vcred_setuid(P, 999), 0); /* the gosu sequence */
    ASSERT_EQ(kbox_vcred_setuid(P, 0), -EPERM);
    ASSERT_EQ(kbox_vcred_setresuid(P, 0, 0, 0), -EPERM);
}

static void test_nonroot_can_swap_within_set(void)
{
    struct kbox_vcred c;
    kbox_vcred_reset_for_test();
    ASSERT_EQ(kbox_vcred_setresuid(P, 5, 6, 7), 0);
    ASSERT_EQ(kbox_vcred_setresuid(P, 6, 7, 5), 0);
    kbox_vcred_get(P, &c);
    ASSERT_EQ(c.ruid, 6);
    ASSERT_EQ(c.euid, 7);
    ASSERT_EQ(c.suid, 5);
}

static void test_setreuid_minus_one_keeps_value(void)
{
    struct kbox_vcred c;
    kbox_vcred_reset_for_test();
    ASSERT_EQ(kbox_vcred_setreuid(P, -1, 42), 0);
    kbox_vcred_get(P, &c);
    ASSERT_EQ(c.ruid, 0);
    ASSERT_EQ(c.euid, 42);
    ASSERT_EQ(c.suid, 42); /* e differs from the old real id */
}

static void test_group_ids_follow_euid_privilege(void)
{
    struct kbox_vcred c;
    kbox_vcred_reset_for_test();
    ASSERT_EQ(kbox_vcred_setgid(P, 101), 0);
    kbox_vcred_get(P, &c);
    ASSERT_EQ(c.egid, 101);
    ASSERT_EQ(kbox_vcred_setuid(P, 101), 0);
    /* setpriv drops the uid first, then the gid, relying on kept capabilities:
     * a process that was root may still change group ids ... */
    ASSERT_EQ(kbox_vcred_setresgid(P, 102, 102, 102), 0);
    /* ... but never regain uid 0. */
    ASSERT_EQ(kbox_vcred_setuid(P, 0), -EPERM);
}

static void test_setpriv_order_uid_then_gid(void)
{
    struct kbox_vcred c;
    kbox_vcred_reset_for_test();
    ASSERT_EQ(kbox_vcred_setresuid(P, 999, 999, 999), 0);
    ASSERT_EQ(kbox_vcred_setresgid(P, 1000, 1000, 1000), 0);
    kbox_vcred_get(P, &c);
    ASSERT_EQ(c.euid, 999);
    ASSERT_EQ(c.egid, 1000);
}

static void test_owner_overlay_wins(void)
{
    struct stat st = {0};
    kbox_vcred_reset_for_test();
    st.st_dev = 7;
    st.st_ino = 12345;
    st.st_uid = getuid();
    st.st_gid = getgid();
    kbox_owner_set(7, 12345, 999, 998);
    kbox_owner_apply(P, &st);
    ASSERT_EQ(st.st_uid, 999);
    ASSERT_EQ(st.st_gid, 998);
}

static void test_owner_default_follows_caller(void)
{
    struct stat st = {0};
    kbox_vcred_reset_for_test();
    st.st_dev = 7;
    st.st_ino = 777;
    st.st_uid = getuid();
    st.st_gid = getgid();
    kbox_owner_apply(P, &st); /* root caller: file looks root-owned */
    ASSERT_EQ(st.st_uid, 0);
    st.st_uid = getuid();
    ASSERT_EQ(kbox_vcred_setuid(P, 101), 0);
    kbox_owner_apply(P, &st); /* uid 101 caller: file looks owned by it */
    ASSERT_EQ(st.st_uid, 101);
}

static void test_owner_foreign_uid_untouched(void)
{
    struct stat st = {0};
    kbox_vcred_reset_for_test();
    st.st_dev = 7;
    st.st_ino = 778;
    st.st_uid = getuid() + 12345;
    kbox_owner_apply(P, &st);
    ASSERT_EQ(st.st_uid, getuid() + 12345);
}

void test_vcred_init(void)
{
    TEST_REGISTER(test_new_pid_is_root);
    TEST_REGISTER(test_root_setuid_sets_all_ids);
    TEST_REGISTER(test_nonroot_cannot_regain_root);
    TEST_REGISTER(test_nonroot_can_swap_within_set);
    TEST_REGISTER(test_setreuid_minus_one_keeps_value);
    TEST_REGISTER(test_group_ids_follow_euid_privilege);
    TEST_REGISTER(test_setpriv_order_uid_then_gid);
    TEST_REGISTER(test_owner_overlay_wins);
    TEST_REGISTER(test_owner_default_follows_caller);
    TEST_REGISTER(test_owner_foreign_uid_untouched);
}
