use super::{assembler::Assembler, parser, RuntimeHealth};
use crate::events::{AgentInfo, EventData, ThreatEvent};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Arc,
};
use std::time::Instant;
use tokio::sync::{mpsc, oneshot};

const AUDIT_NLGRP_READLOG: u32 = 1; // Linux UAPI audit.h, best-effort read-only group.
const MAX_QUEUED_EVENTS: usize = 512;

struct AuditSocket {
    fd: OwnedFd,
    buffer: Vec<u8>,
    receive_buffer_bytes: u32,
}
enum Packet<'a> {
    Idle,
    Data(&'a [u8]),
    Overrun,
    Truncated,
    InvalidSender,
}
impl AuditSocket {
    fn open() -> io::Result<Self> {
        // No NETLINK_NO_ENOBUFS: suppressing overrun notification hides evidence loss.
        let raw = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
                libc::NETLINK_AUDIT,
            )
        };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        let requested: libc::c_int = 4 * 1024 * 1024;
        let rc = unsafe {
            libc::setsockopt(
                fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_RCVBUF,
                (&requested as *const libc::c_int).cast(),
                std::mem::size_of_val(&requested) as libc::socklen_t,
            )
        };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        let mut effective: libc::c_int = 0;
        let mut length = std::mem::size_of_val(&effective) as libc::socklen_t;
        let rc = unsafe {
            libc::getsockopt(
                fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_RCVBUF,
                (&mut effective as *mut libc::c_int).cast(),
                &mut length,
            )
        };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        let mut address: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        address.nl_family = libc::AF_NETLINK as u16;
        address.nl_groups = 1 << (AUDIT_NLGRP_READLOG - 1);
        let rc = unsafe {
            libc::bind(
                fd.as_raw_fd(),
                (&address as *const libc::sockaddr_nl).cast(),
                std::mem::size_of_val(&address) as libc::socklen_t,
            )
        };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        // Never send AUDIT_SET, AUDIT_ADD_RULE or register as auditd's owner.
        Ok(Self {
            fd,
            buffer: vec![0; 128 * 1024],
            receive_buffer_bytes: effective.max(0) as u32,
        })
    }
    fn receive(&mut self) -> io::Result<Packet<'_>> {
        let mut poll = libc::pollfd {
            fd: self.fd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let rc = unsafe { libc::poll(&mut poll, 1, 100) };
        if rc == 0 {
            return Ok(Packet::Idle);
        }
        if rc < 0 {
            let error = io::Error::last_os_error();
            return if error.kind() == io::ErrorKind::Interrupted {
                Ok(Packet::Idle)
            } else {
                Err(error)
            };
        }
        if poll.revents & (libc::POLLNVAL | libc::POLLHUP) != 0 {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "audit_socket_closed",
            ));
        }
        let mut address: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        let mut iov = libc::iovec {
            iov_base: self.buffer.as_mut_ptr().cast(),
            iov_len: self.buffer.len(),
        };
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_name = (&mut address as *mut libc::sockaddr_nl).cast();
        msg.msg_namelen = std::mem::size_of_val(&address) as libc::socklen_t;
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        let received = unsafe {
            libc::recvmsg(
                self.fd.as_raw_fd(),
                &mut msg,
                libc::MSG_DONTWAIT | libc::MSG_TRUNC,
            )
        };
        if received < 0 {
            let error = io::Error::last_os_error();
            return match error.raw_os_error() {
                Some(libc::ENOBUFS) => Ok(Packet::Overrun),
                Some(libc::EINTR | libc::EAGAIN) => Ok(Packet::Idle),
                _ => Err(error),
            };
        }
        // User-space Netlink datagrams cannot impersonate kernel port ID 0.
        if msg.msg_namelen as usize != std::mem::size_of_val(&address)
            || address.nl_family != libc::AF_NETLINK as u16
            || address.nl_pid != 0
        {
            return Ok(Packet::InvalidSender);
        }
        if msg.msg_flags & libc::MSG_TRUNC != 0 || received as usize > self.buffer.len() {
            return Ok(Packet::Truncated);
        }
        Ok(Packet::Data(&self.buffer[..received as usize]))
    }
}

pub(super) fn run(
    agent: AgentInfo,
    tx: mpsc::Sender<ThreatEvent>,
    drops: Arc<AtomicU64>,
    stop: Arc<AtomicBool>,
    health: RuntimeHealth,
    ready: oneshot::Sender<Result<(), ()>>,
) {
    let boot = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .ok()
        .and_then(|v| uuid::Uuid::parse_str(v.trim()).ok())
        .filter(|v| !v.is_nil());
    let Some(boot) = boot else {
        health.fail("audit_boot_identity_failed", None);
        let _ = ready.send(Err(()));
        return;
    };
    let mut socket = match AuditSocket::open() {
        Ok(socket) => socket,
        Err(error) => {
            let code = if matches!(error.raw_os_error(), Some(libc::EPERM | libc::EACCES)) {
                "audit_permission_denied"
            } else {
                "audit_socket_open_failed"
            };
            health.fail(code, error.raw_os_error().map(|v| v as u32));
            let _ = ready.send(Err(()));
            return;
        }
    };
    let mut assembler = Assembler::new(agent, boot);
    assembler.stats.receive_buffer_bytes = socket.receive_buffer_bytes;
    health.linux_audit(assembler.stats.clone());
    health.running();
    if ready.send(Ok(())).is_err() {
        return;
    }
    while !stop.load(Ordering::Acquire) {
        let now = Instant::now();
        let mut output = assembler.expire(now);
        let mut failed = false;
        match socket.receive() {
            Ok(Packet::Idle) => {}
            Ok(Packet::Overrun) => {
                assembler.stats.socket_overruns = assembler.stats.socket_overruns.saturating_add(1)
            }
            Ok(Packet::Truncated) => {
                assembler.stats.truncated_datagrams =
                    assembler.stats.truncated_datagrams.saturating_add(1)
            }
            Ok(Packet::InvalidSender) => {
                health.fail("audit_invalid_sender", None);
                failed = true;
            }
            Ok(Packet::Data(packet)) => match parser::frames(packet) {
                Ok(frames) => {
                    for (kind, payload) in frames {
                        match kind {
                            1 | 3 => {} // NLMSG_NOOP / DONE.
                            4 => {
                                assembler.stats.socket_overruns =
                                    assembler.stats.socket_overruns.saturating_add(1)
                            }
                            2 => {
                                health.fail("audit_netlink_error", None);
                                failed = true;
                            }
                            _ => output.extend(assembler.push(kind, payload, now)),
                        }
                    }
                }
                Err(_) => {
                    assembler.stats.malformed_datagrams =
                        assembler.stats.malformed_datagrams.saturating_add(1)
                }
            },
            Err(error) => {
                health.fail(
                    "audit_receive_failed",
                    error.raw_os_error().map(|v| v as u32),
                );
                failed = true;
            }
        }
        publish(output, &tx, &drops, &health);
        health.linux_audit(assembler.stats.clone());
        if failed {
            break;
        }
    }
    drop(socket); // Unsubscribe before final pending fragments; no global policy change.
    publish(assembler.shutdown(), &tx, &drops, &health);
    health.linux_audit(assembler.stats.clone());
}
fn publish(
    events: Vec<ThreatEvent>,
    tx: &mpsc::Sender<ThreatEvent>,
    drops: &AtomicU64,
    health: &RuntimeHealth,
) {
    for event in events {
        let failed = matches!(&event.data, EventData::LinuxAudit { record } if !record.issues.is_empty()
            || record.records.iter().any(|r| !r.issues.is_empty()));
        health.decoded(false, failed);
        let used = tx.max_capacity() - tx.capacity();
        if used >= MAX_QUEUED_EVENTS || tx.try_send(event).is_err() {
            let _ = drops.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                Some(n.saturating_add(1))
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bounded_queue_reports_event_drops_separately_from_socket_notifications() {
        let (tx, rx) = mpsc::channel(1024);
        let health = RuntimeHealth::new("LinuxAudit");
        let drops = AtomicU64::new(0);
        let mut assembler = Assembler::new(
            AgentInfo {
                hostname: "synthetic".into(),
                agent_id: uuid::Uuid::new_v4(),
            },
            uuid::Uuid::new_v4(),
        );
        assembler.push(1300, b"audit(1.1:1): pid=42 items=0", Instant::now());
        let event = assembler
            .push(1320, b"audit(1.1:1):", Instant::now())
            .pop()
            .unwrap();
        publish(
            vec![event.clone(); MAX_QUEUED_EVENTS + 1],
            &tx,
            &drops,
            &health,
        );
        assert_eq!(rx.len(), MAX_QUEUED_EVENTS);
        assert_eq!(drops.load(Ordering::Relaxed), 1);
        assert_eq!(health.snapshot(1).events_lost_before_queue, 0);
        drop(rx);
        publish(vec![event.clone()], &tx, &drops, &health);
        assert_eq!(drops.load(Ordering::Relaxed), 2);
        drops.store(u64::MAX, Ordering::Relaxed);
        publish(vec![event], &tx, &drops, &health);
        assert_eq!(drops.load(Ordering::Relaxed), u64::MAX);
    }

    #[tokio::test]
    #[ignore = "requires an authorized Linux host, CAP_AUDIT_READ and administrator-provided exec audit rules"]
    async fn linux_audit_live_smoke() {
        use crate::collectors::Collector;
        assert_eq!(
            std::env::var("TF_LINUX_AUDIT_LIVE_TEST").as_deref(),
            Ok("1"),
            "Explicitly opt in on a prepared Linux validation host"
        );
        let agent = AgentInfo {
            hostname: "controlled-linux-test".into(),
            agent_id: uuid::Uuid::new_v4(),
        };
        let mut collector = crate::collectors::linux_audit::LinuxAuditCollector::new(
            crate::config::LinuxAuditConfig { enabled: true },
            agent,
        );
        let (tx, mut rx) = mpsc::channel(1024);
        collector
            .start(tx)
            .await
            .expect("Audit subscription must succeed; denial is not a live-test pass");
        let operation = async {
            let mut child = std::process::Command::new("/bin/true")
                .spawn()
                .expect("benign test executable");
            let pid = child.id();
            assert!(child.wait().unwrap().success());
            while let Some(event) = rx.recv().await {
                if let EventData::LinuxAudit { record } = event.data {
                    if record.pid() == Some(pid)
                        && record.records.iter().any(|r| r.native_type == 1309)
                    {
                        return record;
                    }
                }
            }
            panic!("Audit worker ended before the test exec event");
        };
        let result = tokio::time::timeout(std::time::Duration::from_secs(5), operation).await;
        collector.stop().await.unwrap();
        let record = result.expect(
            "No test exec observed: verify administrator-provided audit rules and namespace",
        );
        assert!(record.boot_id.is_some_and(|v| !v.is_nil()));
        assert!(!record.collection_session_uuid.is_nil());
        assert!(
            record.issues.is_empty(),
            "partial test exec record: {:?}",
            record.issues
        );
        assert_eq!(
            record.completion,
            crate::linux_events::AuditCompletion::EndOfEvent
        );
        let status = collector.status().unwrap();
        assert_eq!(status.state, crate::events::CollectorState::Stopped);
        assert!(!status.linux_audit.unwrap().audit_configuration_verified);
        // No audit rule installation, service changes or raw host-event logging.
    }
    #[test]
    fn uapi_header_layout_matches_portable_decoder() {
        assert_eq!(std::mem::size_of::<libc::nlmsghdr>(), 16);
    }
    #[test]
    #[ignore = "explicit Linux CAP_AUDIT_READ probe; no rule changes"]
    fn linux_audit_permission_probe() {
        match AuditSocket::open() {
            Ok(_) => {
                eprintln!("Linux Audit multicast subscribed and closed; policy was not changed")
            }
            Err(e) => {
                eprintln!("Linux Audit socket errno={:?}", e.raw_os_error());
                assert!(matches!(
                    e.raw_os_error(),
                    Some(libc::EPERM | libc::EACCES | libc::EPROTONOSUPPORT)
                ));
            }
        }
    }
}
