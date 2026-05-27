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
    },
    PassiveProgress {
        done: usize,
        total: usize,
    },
    ActiveProgress {
        done: usize,
        total: usize,
    },
    Finding(Box<Finding>),
    Log(String),
    /// Emitted once per module that executed during the scan. `findings` is
    /// the count this module produced; zero means the module ran but was
    /// quiet (still shown in the Findings-tab tree, folded by default).
    /// See SDD §9.1 for the rendering contract.
    ModuleRan {
        name: String,
        findings: usize,
    },
    /// Reserved for future scan-failure plumbing. The TUI already routes it
    /// to the log pane; no scanner code emits it yet.
    #[allow(dead_code)]
    Error(String),
    Completed {
        duration_secs: f64,
        total_findings: usize,
        risk_score: u8,
        report_path: String,
    },
}
