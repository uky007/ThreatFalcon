//! In-memory acknowledgement barrier for an ordered EventLog batch. The source
//! checkpoint may advance only after all events AND findings reach a durable sink.
use crate::detection::{StateDelta, StateSnapshot};
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    mpsc, Arc, Mutex,
};

#[derive(Debug, PartialEq, Eq)]
pub enum DeliveryResult {
    Committed(StateDelta),
    Failed,
}

#[derive(Debug)]
struct Batch {
    remaining: AtomicUsize,
    failed: AtomicBool,
    completion: Mutex<Option<mpsc::Sender<DeliveryResult>>>,
    restore: Mutex<Option<StateSnapshot>>,
}

#[derive(Debug)]
struct Token {
    batch: Arc<Batch>,
    used: AtomicBool,
}

#[derive(Debug, Clone)]
pub struct Receipt(Arc<Token>);

impl Receipt {
    /// Exactly one token per source event; clones share its once-only state.
    #[allow(dead_code)] // Created by the Windows pull subscription.
    pub fn batch(size: usize) -> (Vec<Self>, mpsc::Receiver<DeliveryResult>) {
        Self::with_restore(size, None)
    }

    pub fn with_restore(
        size: usize,
        restore: Option<StateSnapshot>,
    ) -> (Vec<Self>, mpsc::Receiver<DeliveryResult>) {
        assert!(size > 0);
        let (tx, rx) = mpsc::channel();
        let batch = Arc::new(Batch {
            remaining: AtomicUsize::new(size),
            failed: AtomicBool::new(false),
            completion: Mutex::new(Some(tx)),
            restore: Mutex::new(restore),
        });
        (
            (0..size)
                .map(|_| {
                    Self(Arc::new(Token {
                        batch: batch.clone(),
                        used: AtomicBool::new(false),
                    }))
                })
                .collect(),
            rx,
        )
    }

    pub fn take_restore(&self) -> Option<StateSnapshot> {
        self.0
            .batch
            .restore
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
    }

    #[cfg(all(test, target_os = "windows"))]
    pub fn was_committed(&self) -> bool {
        self.0.batch.remaining.load(Ordering::Acquire) == 0
            && !self.0.batch.failed.load(Ordering::Acquire)
            && self
                .0
                .batch
                .completion
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .is_none()
    }

    /// Called after this event and all findings were written. True means the
    /// caller must sync the sink before calling committed().
    pub fn written(&self) -> bool {
        if self.0.used.swap(true, Ordering::AcqRel) {
            return false;
        }
        self.0.batch.remaining.fetch_sub(1, Ordering::AcqRel) == 1
            && !self.0.batch.failed.load(Ordering::Acquire)
    }

    pub fn committed(&self, state: StateDelta) {
        if self.0.batch.remaining.load(Ordering::Acquire) == 0
            && !self.0.batch.failed.load(Ordering::Acquire)
        {
            self.signal(DeliveryResult::Committed(state));
        }
    }

    pub fn failed(&self) {
        self.0.batch.failed.store(true, Ordering::Release);
        self.signal(DeliveryResult::Failed);
    }

    fn signal(&self, success: DeliveryResult) {
        if let Some(tx) = self
            .0
            .batch
            .completion
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
        {
            let _ = tx.send(success);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cannot_checkpoint_until_every_event_and_sync_complete() {
        let (r, rx) = Receipt::batch(3);
        r[0].committed(StateDelta::empty(uuid::Uuid::nil()));
        assert!(rx.try_recv().is_err());
        assert!(!r[0].written());
        assert!(!r[1].written());
        assert!(rx.try_recv().is_err());
        assert!(r[2].written());
        assert!(rx.try_recv().is_err());
        r[2].committed(StateDelta::empty(uuid::Uuid::nil()));
        assert!(matches!(rx.recv().unwrap(), DeliveryResult::Committed(_)));
    }
    #[test]
    fn clones_cannot_ack_twice_and_failure_cannot_be_overridden() {
        let (r, rx) = Receipt::batch(2);
        let clone = r[0].clone();
        assert!(!r[0].written());
        assert!(!clone.written());
        r[0].failed();
        assert_eq!(rx.recv().unwrap(), DeliveryResult::Failed);
        assert!(!r[1].written());
        r[1].committed(StateDelta::empty(uuid::Uuid::nil()));
        assert!(rx.try_recv().is_err());
    }
    #[test]
    fn sync_failure_does_not_report_success() {
        let (r, rx) = Receipt::batch(1);
        assert!(r[0].written());
        r[0].failed();
        assert_eq!(rx.recv().unwrap(), DeliveryResult::Failed);
    }
    #[test]
    fn receipts_cannot_be_serialized_or_injected_by_untrusted_json() {
        let mut event = crate::fixtures::sysmon(1, 0, crate::fixtures::ACTOR);
        let (mut receipts, rx) = Receipt::batch(1);
        event.delivery = receipts.pop();
        let mut json = serde_json::to_value(&event).unwrap();
        assert!(json.get("delivery").is_none());
        json["delivery"] = serde_json::json!({"committed":true});
        let imported: crate::events::ThreatEvent = serde_json::from_value(json).unwrap();
        assert!(imported.delivery.is_none());
        assert!(rx.try_recv().is_err());
    }
}
