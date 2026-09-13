//! Inspect recorded health without starting collectors or contacting a server.

use std::collections::HashSet;
use std::fs::File;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::Path;

use anyhow::{Context, Result};
use chrono::Utc;
use clap::ValueEnum;
use serde::Serialize;
use uuid::Uuid;

use crate::events::{CollectorError, CollectorState, EventData, ThreatEvent};

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum Language {
    En,
    Ja,
}

impl Language {
    fn text(self, en: &'static str, ja: &'static str) -> &'static str {
        match self {
            Self::En => en,
            Self::Ja => ja,
        }
    }

    fn state(self, state: CollectorState) -> &'static str {
        match state {
            CollectorState::Starting => self.text("Starting", "起動中"),
            CollectorState::Running => self.text("Running", "稼働中"),
            CollectorState::Degraded => self.text("Degraded", "収集品質低下"),
            CollectorState::Stopped => self.text("Stopped", "停止"),
            CollectorState::Disabled => self.text("Disabled", "無効"),
            CollectorState::Unsupported => self.text("Unsupported", "未対応OS"),
            CollectorState::Error => self.text("Error", "エラー"),
        }
    }

    fn error(self, code: &str) -> &'static str {
        match code {
            "etw_start_failed" => self.text(
                "ETW session could not start",
                "ETWセッションの起動に失敗しました",
            ),
            "etw_open_failed" => self.text(
                "ETW consumer could not open",
                "ETWイベントの購読に失敗しました",
            ),
            "etw_no_providers" => self.text(
                "No ETW providers enabled",
                "有効化できたETWプロバイダがありません",
            ),
            "etw_consumer_ended" => self.text(
                "ETW consumer ended unexpectedly",
                "ETW収集処理が予期せず終了しました",
            ),
            "etw_query_failed" => self.text(
                "ETW statistics unavailable; previous sample retained",
                "ETW統計を取得できません。前回の値を保持しています",
            ),
            "etw_stop_failed" => self.text(
                "ETW session could not stop",
                "ETWセッションの停止に失敗しました",
            ),
            "sysmon_signal_failed" => self.text(
                "Sysmon signal could not be created",
                "Sysmon通知用オブジェクトの作成に失敗しました",
            ),
            "sysmon_subscribe_failed" => self.text(
                "Sysmon subscription failed; check installation and permissions",
                "Sysmon購読に失敗しました。インストール状態と権限を確認してください",
            ),
            "sysmon_subscription_error" => self.text(
                "Sysmon subscription reported an error",
                "Sysmon購読中にエラーが通知されました",
            ),
            "sysmon_recovery_failed" => self.text(
                "Sysmon recovery stopped; inspect checkpoint identity, log retention and output errors. No automatic cursor reset",
                "Sysmon復旧を停止しました。保存位置・元ログの保持・出力エラーを確認してください。保存位置は自動リセットしません",
            ),
            "sysmon_start_timeout" => self.text(
                "Sysmon subscription did not become ready",
                "Sysmon購読の準備完了を確認できませんでした",
            ),
            "sysmon_callback_panic" => self.text(
                "Sysmon callback panicked; source evidence may be missing",
                "Sysmon処理でパニックが発生し、元イベントが欠落した可能性があります",
            ),
            "collector_worker_ended" | "collector_worker_failed" => self.text(
                "Collector worker failed or ended unexpectedly",
                "収集処理が失敗または予期せず終了しました",
            ),
            "collector_stop_timeout" => self.text(
                "Collector shutdown timed out",
                "収集処理の停止がタイムアウトしました",
            ),
            _ => self.text(
                "Collector failed; inspect sensor logs",
                "収集処理に失敗しました。センサログを確認してください",
            ),
        }
    }
}

#[derive(Serialize)]
struct HealthReport {
    event: ThreatEvent,
    age_secs: i64,
    stale: bool,
    clock_skew: bool,
    skipped_lines: u64,
}

fn read_latest(path: &Path, agent_id: Option<Uuid>, max_age_secs: u64) -> Result<HealthReport> {
    let mut reader = BufReader::new(
        File::open(path).context("Cannot open health input / ヘルス入力を開けません")?,
    );
    let mut latest = None;
    let mut agents = HashSet::new();
    let mut skipped_lines = 0;
    let mut line = Vec::new();
    loop {
        line.clear();
        let n = reader
            .by_ref()
            .take(4 * 1024 * 1024 + 1)
            .read_until(b'\n', &mut line)?;
        if n == 0 {
            break;
        }
        anyhow::ensure!(
            n <= 4 * 1024 * 1024,
            "JSONL line exceeds 4 MiB safety limit / JSONLの行サイズが上限を超えています"
        );
        if line.iter().all(|b| b.is_ascii_whitespace()) {
            continue;
        }
        // A crash may split a UTF-8 character; count that partial line without
        // losing access to subsequent intact health records after restart.
        let event: ThreatEvent = match serde_json::from_slice(&line) {
            Ok(event) => event,
            Err(_) => {
                skipped_lines += 1;
                continue;
            }
        };
        if !matches!(event.data, EventData::SensorHealth { .. }) {
            continue;
        }
        if agent_id.is_some_and(|id| id != event.agent_id) {
            continue;
        }
        agents.insert(event.agent_id);
        if agents.len() > 1 {
            anyhow::bail!("Multiple agents: specify --agent-id / 複数のエージェントがあります。--agent-id を指定してください");
        }
        // Append order deliberately survives backwards adjustments of the host clock.
        latest = Some(event);
    }
    let event = latest
        .context("No matching SensorHealth event / 対象のSensorHealthイベントがありません")?;
    let age_secs = Utc::now()
        .signed_duration_since(event.timestamp)
        .num_seconds();
    Ok(HealthReport {
        event,
        age_secs,
        stale: age_secs >= 0 && age_secs as u64 > max_age_secs,
        clock_skew: age_secs < -60,
        skipped_lines,
    })
}

pub fn run(
    path: &Path,
    agent_id: Option<Uuid>,
    lang: Language,
    json: bool,
    max_age_secs: u64,
) -> Result<()> {
    let report = read_latest(path, agent_id, max_age_secs)?;
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    if json {
        serde_json::to_writer_pretty(&mut out, &report)?;
        writeln!(out)?;
        return Ok(());
    }
    writeln!(
        out,
        "{}: {} ({})",
        lang.text("Sensor health", "センサ稼働状況"),
        report.event.hostname,
        report.event.agent_id
    )?;
    writeln!(
        out,
        "{}: {}",
        lang.text("Recorded at", "記録時刻"),
        report.event.timestamp
    )?;
    if report.stale {
        writeln!(
            out,
            "{}",
            lang.text(
                "STALE: this record does not confirm current operation",
                "記録が古いため、現在の稼働状態は確認できません"
            )
        )?;
    }
    if report.clock_skew {
        writeln!(
            out,
            "{}",
            lang.text(
                "Clock skew: record is in the future; check host clocks",
                "記録時刻が未来です。端末の時計を確認してください"
            )
        )?;
    }
    if report.skipped_lines > 0 {
        writeln!(
            out,
            "{}: {}",
            lang.text("Unreadable lines skipped", "読み取れなかった行数"),
            report.skipped_lines
        )?;
    }
    if let EventData::SensorHealth {
        events_total,
        events_dropped,
        collectors,
        sink,
        ..
    } = &report.event.data
    {
        writeln!(
            out,
            "{}: {} / {}: {}",
            lang.text("Processed events", "処理イベント数"),
            events_total,
            lang.text("Known event drops", "把握できたイベント欠落数"),
            events_dropped
        )?;
        for c in collectors {
            writeln!(
                out,
                "{}: {} ({})",
                c.name,
                lang.state(c.state),
                lang.text("recorded state", "記録時点の状態")
            )?;
            writeln!(
                out,
                "  {}: {}",
                lang.text("Queue event drops", "キューでのイベント欠落数"),
                c.queue_events_dropped
            )?;
            writeln!(
                out,
                "  {}: {}",
                lang.text("Events lost before queue", "キュー投入前の欠落"),
                c.events_lost_before_queue
            )?;
            for error in [&c.error, &c.statistics_error].into_iter().flatten() {
                render_error(&mut out, lang, error)?;
            }
            writeln!(
                out,
                "  {}: {} / {} / {}",
                lang.text(
                    "Observed / native-only / decode failures",
                    "観測 / 未正規化 / 解析失敗"
                ),
                c.events_observed,
                c.events_not_normalized,
                c.decode_failures
            )?;
            for p in &c.providers {
                writeln!(
                    out,
                    "  {}: {}{}",
                    p.name,
                    if p.enabled {
                        lang.text("Enabled", "有効化成功")
                    } else {
                        lang.text("Enable failed", "有効化失敗")
                    },
                    p.error_code
                        .map(|v| format!(" (OS: {v})"))
                        .unwrap_or_default()
                )?;
            }
            if let Some(mode) = &c.recovery_mode {
                let description = match mode.as_str() {
                    "acknowledged_file_checkpoint" => lang.text(
                        "Acknowledged file checkpoint",
                        "ファイル保存確認後に再開位置を更新",
                    ),
                    "future_only" => lang.text(
                        "Live only (no restart recovery)",
                        "ライブ収集のみ（再起動復旧なし）",
                    ),
                    _ => mode,
                };
                writeln!(
                    out,
                    "  {}: {}",
                    lang.text("Recovery mode", "復旧方式"),
                    description
                )?;
                writeln!(
                    out,
                    "  {}: {}",
                    lang.text(
                        "Source events checkpointed this run",
                        "今回の実行で保存位置を確定した元イベント数"
                    ),
                    c.checkpoint_committed_events
                )?;
                if let Some(at) = c.checkpoint_last_commit_at {
                    writeln!(
                        out,
                        "  {}: {}",
                        lang.text("Last checkpoint commit", "最後の保存位置確定"),
                        at
                    )?;
                }
            }
            if let Some(s) = &c.etw {
                writeln!(
                    out,
                    "  {}: {}",
                    lang.text("ETW sample time", "ETW統計の取得時刻"),
                    s.collected_at
                )?;
                writeln!(
                    out,
                    "  {}: {}",
                    lang.text("ETW events lost", "ETWイベント欠落数"),
                    s.events_lost
                )?;
                writeln!(
                    out,
                    "  {}: {} / {}: {}",
                    lang.text("Real-time buffers lost", "リアルタイムバッファ欠落数"),
                    s.realtime_buffers_lost,
                    lang.text("Log buffers lost", "ログバッファ欠落数"),
                    s.log_buffers_lost
                )?;
            }
        }
        if let Some(s) = sink {
            writeln!(
                out,
                "{}: {} / {}: {} / {}: {}",
                lang.text("Output", "出力先"),
                s.sink_type,
                lang.text("Output drops", "出力時の欠落数"),
                s.events_dropped,
                lang.text("Spool bytes", "送信待ちバイト数"),
                s.spool_bytes
            )?;
        }
    }
    if let Some(stats) = &report.event.analysis_status {
        writeln!(
            out,
            "{}: {} / {}: {}",
            lang.text("Analysis state restored", "相関状態の復元"),
            if stats.state_restored {
                lang.text("Yes", "あり")
            } else {
                lang.text("No", "なし")
            },
            lang.text("Restored process timelines", "復元したプロセス時系列数"),
            stats.restored_timelines
        )?;
        writeln!(
            out,
            "{}: eligible={} missing={} late={} capacity_drops={} findings={}",
            lang.text("Correlation status", "相関分析の状態"),
            stats.eligible_events,
            stats.missing_evidence_events,
            stats.late_events,
            stats.capacity_events_dropped,
            stats.findings
        )?;
    }
    Ok(())
}

fn render_error(out: &mut impl Write, lang: Language, error: &CollectorError) -> Result<()> {
    writeln!(
        out,
        "  {} [{}]{}",
        lang.error(&error.code),
        error.code,
        error
            .os_code
            .map(|v| format!(" (OS: {v:#x})"))
            .unwrap_or_default()
    )?;
    Ok(())
}
