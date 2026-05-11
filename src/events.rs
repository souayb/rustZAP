use crate::types::Finding;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanPhase {
    Spider,
    Passive,
    Active,
    Done,
}

impl ScanPhase {
    pub fn label(&self) -> &'static str {
        match self {
            ScanPhase::Spider => "SPIDER",
            ScanPhase::Passive => "PASSIVE",
            ScanPhase::Active => "ACTIVE",
            ScanPhase::Done => "DONE",
        }
    }
}

#[derive(Debug, Clone)]
pub enum ScanEvent {
    Started {
        target: String,
    },
    PhaseStarted {
        phase: ScanPhase,
        total: Option<usize>,
    },
    SpiderProgress {
        discovered: usize,
        message: String,
    },
    PassiveProgress {
        done: usize,
        total: usize,
    },
    ActiveProgress {
        done: usize,
        total: usize,
    },
    Finding(Finding),
    Log(String),
    Error(String),
    Completed {
        duration_secs: f64,
        total_findings: usize,
        risk_score: u8,
        report_path: String,
    },
}
