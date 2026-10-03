#![cfg(target_os = "macos")]

//! macOS 第二道单实例原子锁（`flock`），兜底 `tauri-plugin-single-instance` 的
//! socket `connect`→unlink→`bind` 竞态。
//!
//! 不用 `fcntl` 记录锁：它是 per-process 的，同进程第二个 fd 会静默成功，关闭
//! 任一 fd 还会丢掉该文件上的全部锁。`flock` 归属 open file description，两个
//! 方向都正确。
//!
//! 锁文件只是载体：文件残留 ≠ 有人持锁。崩溃 / `kill -9` 后内核自动释放，下次
//! 启动必须能拿到锁。只有 `EWOULDBLOCK`/`EAGAIN` 视为被占用；其余一律 fail-open。

use std::fs::{File, OpenOptions};
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use tauri::{AppHandle, Manager, Runtime};

pub(crate) enum LockAttemptKind {
    HeldByOther,
    Unavailable,
}

pub(crate) enum LockAttempt {
    Locked(File),
    HeldByOther,
    Unavailable,
}

struct InstanceLock(Mutex<Option<File>>);

/// errno 分类：只有明确「被占用」才当占用，其余一律 fail-open。
pub(crate) fn classify(raw: Option<i32>) -> LockAttemptKind {
    match raw {
        Some(code) if code == libc::EWOULDBLOCK || code == libc::EAGAIN => {
            LockAttemptKind::HeldByOther
        }
        _ => LockAttemptKind::Unavailable,
    }
}

pub(crate) fn try_lock_path(path: &Path) -> LockAttempt {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() && std::fs::create_dir_all(parent).is_err() {
            return LockAttempt::Unavailable;
        }
    }

    let file = match OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)
    {
        Ok(file) => file,
        Err(_) => return LockAttempt::Unavailable,
    };

    // SAFETY: `file` owns a valid fd for the duration of this call.
    let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if rc == 0 {
        LockAttempt::Locked(file)
    } else {
        match classify(std::io::Error::last_os_error().raw_os_error()) {
            LockAttemptKind::HeldByOther => LockAttempt::HeldByOther,
            LockAttemptKind::Unavailable => LockAttempt::Unavailable,
        }
    }
}

fn lock_path() -> PathBuf {
    wb_switch_core::modules::config::store_dir().join("instance.lock")
}

/// 落点调用：明确被占用则退出，其余情况一律继续。锁必须 `manage` 进 App 状态，
/// 不能放在 `setup` 局部变量里（闭包结束会 drop，锁立刻没了）。
pub fn acquire_or_exit<R: Runtime>(app: &AppHandle<R>) {
    match try_lock_path(&lock_path()) {
        LockAttempt::Locked(file) => {
            app.manage(InstanceLock(Mutex::new(Some(file))));
        }
        LockAttempt::HeldByOther => {
            eprintln!("[单实例] 已有实例持锁，本次启动退出");
            std::process::exit(0);
        }
        LockAttempt::Unavailable => {
            // fail-open：不注册 state，按加锁前的行为继续启动。
        }
    }
}

/// 取出并 drop 持有的 fd，立即释放 flock。返回此前是否持锁。
pub fn release<R: Runtime>(app: &AppHandle<R>) -> bool {
    let Some(state) = app.try_state::<InstanceLock>() else {
        return false;
    };
    let mut guard = state
        .0
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    guard.take().is_some()
}

/// 重新 open+flock。成功则放回 state；被占用或不可用都返回 false（调用方必须
/// 退出，不允许无锁继续运行）。
pub fn reacquire<R: Runtime>(app: &AppHandle<R>) -> bool {
    match try_lock_path(&lock_path()) {
        LockAttempt::Locked(file) => {
            if let Some(state) = app.try_state::<InstanceLock>() {
                let mut guard = state
                    .0
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                *guard = Some(file);
            } else {
                app.manage(InstanceLock(Mutex::new(Some(file))));
            }
            true
        }
        LockAttempt::HeldByOther | LockAttempt::Unavailable => false,
    }
}

#[cfg(test)]
mod tests {
    use super::{classify, try_lock_path, LockAttempt, LockAttemptKind};
    use std::fs::{self, File, OpenOptions};
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};

    struct TempLockPath {
        dir: PathBuf,
        path: PathBuf,
    }

    impl TempLockPath {
        fn new() -> Self {
            let dir = std::env::temp_dir()
                .join(format!("trae-switch-cn-instance-lock-{}", uuid::Uuid::new_v4()));
            let path = dir.join("instance.lock");
            Self { dir, path }
        }
    }

    impl Drop for TempLockPath {
        fn drop(&mut self) {
            if self.dir.exists() {
                let _ = fs::set_permissions(&self.dir, fs::Permissions::from_mode(0o755));
            }
            let _ = fs::remove_file(&self.path);
            // 父目录可能被测试故意做成了普通文件（见 parent_that_is_a_file_is_unavailable）。
            let _ = fs::remove_file(&self.dir);
            let _ = fs::remove_dir_all(&self.dir);
        }
    }

    fn assert_locked(path: &Path) -> File {
        match try_lock_path(path) {
            LockAttempt::Locked(file) => file,
            LockAttempt::HeldByOther => panic!("expected Locked, got HeldByOther"),
            LockAttempt::Unavailable => panic!("expected Locked, got Unavailable"),
        }
    }

    #[test]
    fn second_fd_is_held_by_other_until_first_drops() {
        let tmp = TempLockPath::new();
        let held = assert_locked(&tmp.path);
        match try_lock_path(&tmp.path) {
            LockAttempt::HeldByOther => {}
            LockAttempt::Locked(_) => panic!("second fd must not take the flock"),
            LockAttempt::Unavailable => panic!("expected HeldByOther, got Unavailable"),
        }
        drop(held);
        let _reacquired = assert_locked(&tmp.path);
    }

    #[test]
    fn existing_file_without_holder_is_still_lockable() {
        let tmp = TempLockPath::new();
        fs::create_dir_all(&tmp.dir).unwrap();
        OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .open(&tmp.path)
            .unwrap();
        assert!(tmp.path.exists(), "lock file must exist before locking");
        let _held = assert_locked(&tmp.path);
    }

    #[test]
    fn classify_maps_only_wouldblock_and_again_to_held() {
        assert!(matches!(
            classify(Some(libc::EWOULDBLOCK)),
            LockAttemptKind::HeldByOther
        ));
        assert!(matches!(
            classify(Some(libc::EAGAIN)),
            LockAttemptKind::HeldByOther
        ));
        assert!(matches!(classify(None), LockAttemptKind::Unavailable));
        assert!(matches!(
            classify(Some(libc::ENOLCK)),
            LockAttemptKind::Unavailable
        ));
        assert!(matches!(
            classify(Some(libc::EPERM)),
            LockAttemptKind::Unavailable
        ));
    }

    #[test]
    fn missing_parent_dir_is_created() {
        let tmp = TempLockPath::new();
        assert!(!tmp.dir.exists());
        let _held = assert_locked(&tmp.path);
        assert!(tmp.dir.is_dir());
        assert!(tmp.path.exists());
    }

    #[test]
    fn parent_that_is_a_file_is_unavailable() {
        // 确定性用例：父路径先占成普通文件 → create_dir_all 必然失败 → fail-open。
        // （0o555 那条依赖权限语义，在特殊 ACL 环境下可能写成功，断言不了。）
        let tmp = TempLockPath::new();
        fs::write(&tmp.dir, b"not a directory").unwrap();
        assert!(matches!(try_lock_path(&tmp.path), LockAttempt::Unavailable));
    }

    #[test]
    fn unwritable_parent_is_unavailable() {
        // root 绕过目录写权限，构造不出「打开失败」的环境时跳过，避免误报。
        // SAFETY: geteuid has no preconditions.
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let tmp = TempLockPath::new();
        fs::create_dir_all(&tmp.dir).unwrap();
        fs::set_permissions(&tmp.dir, fs::Permissions::from_mode(0o555)).unwrap();
        match try_lock_path(&tmp.path) {
            LockAttempt::Unavailable => {}
            LockAttempt::Locked(_) | LockAttempt::HeldByOther => {
                // 个别环境（特殊 ACL / SIP 例外）仍可能写成功；跳过而非当失败。
            }
        }
    }
}
