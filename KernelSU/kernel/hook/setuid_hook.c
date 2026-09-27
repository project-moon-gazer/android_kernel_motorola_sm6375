#ifdef CONFIG_KSU_SUSFS
static inline bool is_zygote_isolated_service_uid(uid_t uid)
{
	uid %= 100000;
	return (uid >= 99000 && uid < 100000);
}

static inline bool is_zygote_normal_app_uid(uid_t uid)
{
	uid %= 100000;
	return (uid >= 10000 && uid < 19999);
}

extern u32 susfs_zygote_sid;
extern struct work_struct susfs_extra_works;

static inline void ksu_handle_extra_susfs_work(void)
{
	if (work_pending(&susfs_extra_works))
		return;

	schedule_work(&susfs_extra_works);
}
#endif // #ifdef CONFIG_KSU_SUSFS

static __always_inline void ksu_handle_setresuid_cred(struct cred *new, const struct cred *old)
{
	if (!new || !old)
		return;

	uid_t new_uid = ksu_get_uid_t(new->uid);
	uid_t old_uid = ksu_get_uid_t(old->uid);

	// old process is not root, ignore it.
	if (unlikely(!!old_uid))
		return;

#ifdef CONFIG_KSU_SUSFS
	// We only interest in process spawned by zygote
	if (!susfs_is_sid_equal(current_cred(), susfs_zygote_sid))
		return;

#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT
	// Isolated service: force umount
	if (is_zygote_isolated_service_uid(new_uid))
		goto do_umount;
#endif // #ifdef CONFIG_KSU_SUSFS_SUS_MOUNT
#endif // #ifdef CONFIG_KSU_SUSFS

	if (IS_ENABLED(CONFIG_KSU_DEBUG))
		pr_info("handle_setresuid from %d to %d\n", old_uid, new_uid);

	// we dont have those new fancy things upstream has
	// lets just do the original thing where we disable seccomp
	if (unlikely(is_uid_manager(new_uid)))
		goto install_ksu_fd;

#ifdef CONFIG_KSU_SUSFS
	// Normal user app that needs to be umounted
	if (likely(is_zygote_normal_app_uid(new_uid) && ksu_uid_should_umount(new_uid)))
		goto do_umount;
#endif // #ifdef CONFIG_KSU_SUSFS

	if (ksu_is_allow_uid_for_current(new_uid))
		goto kill_seccomp;

#ifdef CONFIG_KSU_SUSFS
	return;

do_umount:
#endif
	// Handle kernel umount
	ksu_handle_umount(new, old);

#ifdef CONFIG_KSU_SUSFS
	ksu_handle_extra_susfs_work();
	susfs_set_current_proc_umounted();
#endif // #ifdef CONFIG_KSU_SUSFS
	return;

install_ksu_fd:
	pr_info("install fd for manager: %d\n", new_uid);
	ksu_install_fd();

kill_seccomp:
	disable_seccomp();
	set_thread_flag(TIF_KSU_MANAGED); // sucompat fast-path
	return;
}
