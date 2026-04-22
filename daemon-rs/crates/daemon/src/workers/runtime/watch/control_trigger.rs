use std::{
    future::Future,
    path::PathBuf,
    pin::Pin,
    sync::Arc,
    time::Duration,
};

use tokio_util::sync::CancellationToken;

use crate::utils::nul_terminated::nul_terminated_utf8;

pub(super) fn spawn_watch_trigger_task<F>(
    shutdown: CancellationToken,
    poll_interval: Duration,
    targets: Vec<PathBuf>,
    empty_targets_behavior: super::EmptyWatchTargetsBehavior,
    mut on_scan_trigger: F,
) -> tokio::task::JoinHandle<()>
where
    F: FnMut(bool) -> Pin<Box<dyn Future<Output = ()> + Send>> + Send + 'static,
{
    tokio::spawn(async move {
        let (_watcher, mut fs_rx_enabled, mut fs_rx) =
            setup_fs_trigger(&targets, empty_targets_behavior);

        loop {
            let mut should_scan = false;
            let mut is_inotify = false;
            tokio::select! {
                _ = shutdown.cancelled() => break,
                _ = tokio::time::sleep(poll_interval) => {
                    should_scan = true;
                }
                event = fs_rx.recv(), if fs_rx_enabled => {
                    match event {
                        Some(()) => { should_scan = true; is_inotify = true; }
                        None => {
                            fs_rx_enabled = false;
                            tracing::warn!(interval = ?poll_interval, "filesystem watch channel closed, continuing with poll-only fallback");
                        }
                    }
                }
            }

            if !should_scan {
                continue;
            }

            on_scan_trigger(is_inotify).await;
        }
    })
}

fn setup_fs_trigger(
    paths: &[PathBuf],
    empty_targets_behavior: super::EmptyWatchTargetsBehavior,
) -> (
    Option<InotifyTrigger>,
    bool,
    tokio::sync::mpsc::Receiver<()>,
) {
    let (tx, rx) = tokio::sync::mpsc::channel(1);

    let fd = {
        let flags = nix::libc::IN_NONBLOCK | nix::libc::IN_CLOEXEC;
        // SAFETY: Calling libc syscall with constant flags and checking return value.
        let created = unsafe { nix::libc::inotify_init1(flags) };
        if created < 0 {
            let err = std::io::Error::last_os_error();
            tracing::warn!("failed to initialize inotify, using poll-only fallback: {err}");
            return (None, false, rx);
        }
        created
    };

    let mut watched_any = false;
    let mask = nix::libc::IN_CREATE
        | nix::libc::IN_MODIFY
        | nix::libc::IN_DELETE
        | nix::libc::IN_MOVED_FROM
        | nix::libc::IN_MOVED_TO
        | nix::libc::IN_CLOSE_WRITE
        | nix::libc::IN_DELETE_SELF
        | nix::libc::IN_MOVE_SELF;

    for path in paths {
        let c_path = match std::ffi::CString::new(path.as_os_str().as_encoded_bytes()) {
            Ok(v) => v,
            Err(_) => {
                tracing::warn!(path = %path.display(), "failed to watch path with interior NUL, keeping poll fallback");
                continue;
            }
        };

        // SAFETY: fd is valid from inotify_init1; c_path is a valid C string.
        let watch_rc = unsafe { nix::libc::inotify_add_watch(fd, c_path.as_ptr(), mask) };
        if watch_rc >= 0 {
            watched_any = true;
        } else {
            let err = std::io::Error::last_os_error();
            tracing::warn!(path = %path.display(), "failed to watch filesystem path, keeping poll fallback: {err}");
        }
    }

    if !watched_any {
        // SAFETY: fd was created by inotify_init1 and is no longer needed.
        unsafe {
            nix::libc::close(fd);
        }
        match empty_targets_behavior {
            super::EmptyWatchTargetsBehavior::WarnPollFallback => {
                tracing::warn!("no filesystem watch targets registered, using poll-only fallback");
            }
            super::EmptyWatchTargetsBehavior::InfoPollFallback => {
                tracing::info!(
                    "no filesystem watch targets registered by design, using poll-only fallback"
                );
            }
        }
        return (None, false, rx);
    }

    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let stop_thread = stop.clone();
    let worker = std::thread::spawn(move || {
        let mut buffer = [0_u8; 4096];

        // Use epoll to wait for inotify events with near-zero latency instead of sleeping.
        // SAFETY: epoll_create1 with EPOLL_CLOEXEC; return value checked below.
        let epoll_fd = unsafe { nix::libc::epoll_create1(nix::libc::EPOLL_CLOEXEC) };
        let use_epoll = if epoll_fd >= 0 {
            let mut ev = nix::libc::epoll_event {
                events: nix::libc::EPOLLIN as u32,
                u64: 0,
            };
            // SAFETY: epoll_fd and fd are both valid; ev is properly initialised.
            let rc =
                unsafe { nix::libc::epoll_ctl(epoll_fd, nix::libc::EPOLL_CTL_ADD, fd, &mut ev) };
            rc >= 0
        } else {
            false
        };

        while !stop_thread.load(std::sync::atomic::Ordering::Relaxed) {
            if use_epoll {
                // Block until the inotify fd is readable or the 10 ms timeout expires so
                // we can re-check the stop flag without busy-spinning.
                let mut events = [nix::libc::epoll_event { events: 0, u64: 0 }; 1];
                // SAFETY: epoll_fd is valid; events slice is writable and correctly sized.
                let n = unsafe { nix::libc::epoll_wait(epoll_fd, events.as_mut_ptr(), 1, 10) };
                if n <= 0 {
                    continue;
                }
            }

            // SAFETY: fd is a live inotify descriptor; buffer is writable and sized correctly.
            let bytes_read = unsafe {
                nix::libc::read(
                    fd,
                    buffer.as_mut_ptr().cast::<nix::libc::c_void>(),
                    buffer.len(),
                )
            };

            if bytes_read < 0 {
                let err = std::io::Error::last_os_error();
                if err.kind() != std::io::ErrorKind::WouldBlock {
                    tracing::warn!("inotify read failed, keeping poll fallback active: {err}");
                    break;
                }
                if !use_epoll {
                    std::thread::sleep(Duration::from_millis(10));
                }
                continue;
            }

            if bytes_read == 0 {
                if !use_epoll {
                    std::thread::sleep(Duration::from_millis(10));
                }
                continue;
            }

            let mut offset = 0_usize;
            let mut emit = false;
            let header_size = std::mem::size_of::<nix::libc::inotify_event>();
            while offset + header_size <= bytes_read as usize {
                // SAFETY: offset bounds are checked above for inotify_event header size.
                let event = unsafe {
                    std::ptr::read_unaligned(
                        buffer[offset..].as_ptr().cast::<nix::libc::inotify_event>(),
                    )
                };
                let name = if event.len > 0 {
                    let name_start = offset + header_size;
                    let name_end = name_start.saturating_add(event.len as usize);
                    if name_end <= bytes_read as usize {
                        let raw_name = &buffer[name_start..name_end];
                        nul_terminated_utf8(raw_name)
                    } else {
                        None
                    }
                } else {
                    None
                };

                let is_transient = name.is_some_and(super::is_transient_watch_event_name);
                if super::should_forward_inotify_mask(event.mask) && !is_transient {
                    emit = true;
                }

                let event_size = header_size + event.len as usize;
                if event_size == 0 {
                    break;
                }
                offset = offset.saturating_add(event_size);
            }

            if emit {
                let _ = tx.try_send(());
            }
        }

        // SAFETY: epoll_fd was created in this function and should be closed once worker exits.
        if use_epoll {
            unsafe { nix::libc::close(epoll_fd) };
        }
        // SAFETY: fd was created in this function and should be closed once worker exits.
        unsafe {
            nix::libc::close(fd);
        }
    });

    (
        Some(InotifyTrigger {
            stop,
            worker: Some(worker),
        }),
        true,
        rx,
    )
}

struct InotifyTrigger {
    stop: Arc<std::sync::atomic::AtomicBool>,
    worker: Option<std::thread::JoinHandle<()>>,
}

impl Drop for InotifyTrigger {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::Relaxed);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}
