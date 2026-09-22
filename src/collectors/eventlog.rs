//! Bounded notification waits for Windows Event Log pull subscriptions.
use std::sync::atomic::{AtomicBool, Ordering};
use windows::{
    core::{Error, Result},
    Win32::{
        Foundation::{E_UNEXPECTED, HANDLE, WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT},
        System::Threading::{ResetEvent, WaitForSingleObject},
    },
};

/// Call after draining EvtNext to ERROR_NO_MORE_ITEMS (or ERROR_TIMEOUT).
/// A wait timeout only lets us check shutdown; it is not permission to call
/// EvtNext again. Reading an exhausted subscription without a notification can
/// fail with ERROR_INVALID_OPERATION, even though the subscription is healthy.
/// Reset once after draining, as in the SDK pull-subscription sequence, then
/// keep waiting for a new signal. All handles remain on the owning worker.
pub(super) fn wait_for_events(signal: HANDLE, stop: &AtomicBool) -> Result<bool> {
    unsafe { ResetEvent(signal)? };
    while !stop.load(Ordering::Acquire) {
        match unsafe { WaitForSingleObject(signal, 100) } {
            WAIT_OBJECT_0 => return Ok(!stop.load(Ordering::Acquire)),
            WAIT_TIMEOUT => continue,
            WAIT_FAILED => return Err(Error::from_win32()),
            _ => return Err(Error::new(E_UNEXPECTED, "unexpected Event Log wait result")),
        }
    }
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
        time::Duration,
    };
    use windows::Win32::System::Threading::{CreateEventW, SetEvent};

    fn signal() -> OwnedHandle {
        // Own the event for the entire scoped-thread lifetime.
        unsafe { OwnedHandle::from_raw_handle(CreateEventW(None, true, true, None).unwrap().0) }
    }

    #[test]
    fn timeouts_keep_waiting_until_stop() {
        let signal = signal();
        let stop = AtomicBool::new(false);
        std::thread::scope(|scope| {
            scope.spawn(|| {
                std::thread::sleep(Duration::from_millis(350));
                stop.store(true, Ordering::Release);
            });
            assert!(!wait_for_events(HANDLE(signal.as_raw_handle()), &stop).unwrap());
        });
    }

    #[test]
    fn notification_after_timeouts_resumes_reading() {
        let signal = signal();
        let stop = AtomicBool::new(false);
        let (done, completed) = std::sync::mpsc::channel();
        std::thread::scope(|scope| {
            let (signal_ref, stop_ref) = (&signal, &stop);
            let notifier = scope.spawn(move || {
                std::thread::sleep(Duration::from_millis(350));
                let result = unsafe { SetEvent(HANDLE(signal_ref.as_raw_handle())) };
                // Bound the test even if notification handling regresses.
                let _ = completed.recv_timeout(Duration::from_secs(2));
                stop_ref.store(true, Ordering::Release);
                result
            });
            let notified = wait_for_events(HANDLE(signal.as_raw_handle()), &stop);
            let _ = done.send(());
            notifier.join().unwrap().unwrap();
            assert!(notified.unwrap());
        });
    }

    #[test]
    fn already_stopped_does_not_wait() {
        let signal = signal();
        assert!(!wait_for_events(HANDLE(signal.as_raw_handle()), &AtomicBool::new(true)).unwrap());
    }
}
