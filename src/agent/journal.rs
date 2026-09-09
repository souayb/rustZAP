//! Durable task receipts. An intent is flushed before execution; an interrupted
//! task remains visibly unsettled and must never be blindly replayed.
use anyhow::Result;
use serde_json::{json, Value};
use std::{
    fs::{File, OpenOptions},
    io::Write,
    path::PathBuf,
};

pub struct TaskJournal {
    file: File,
    pub path: PathBuf,
}
impl TaskJournal {
    pub fn create(output: &str) -> Result<Self> {
        let path = PathBuf::from(format!("{output}.tasks-{}.jsonl", crate::types::uuid_v4()));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options.open(&path)?;
        Ok(Self { file, path })
    }
    pub fn append(&mut self, event: Value) -> Result<()> {
        let event = crate::agent::trace::redact(&event);
        serde_json::to_writer(&mut self.file, &event)?;
        self.file.write_all(b"\n")?;
        self.file.sync_data()?;
        Ok(())
    }
    pub fn observation(&mut self, turn: u32, id: usize, tool: &str, result: &Value) -> Result<()> {
        self.append(json!({"event":"observation", "task_id":format!("task-{turn}"),
            "evidence_id":format!("obs-{id}"), "tool":tool,
            "status": if result.get("error").is_some() {"failed"} else if result.get("note").is_some() {"skipped"} else {"succeeded"},
            "result":result}))
    }
}
