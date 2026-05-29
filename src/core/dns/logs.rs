use std::future::Future;

use crate::core::error::Result;

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    serde::Serialize,
    serde::Deserialize,
    clap::ValueEnum,
)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warning,
    Error,
    Critical,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LogLine {
    pub timestamp: String,
    pub level: LogLevel,
    pub title: Option<String>,
    pub message: String,
}

#[derive(Debug, Clone, Default)]
pub struct LogsOptions {
    pub lines: Option<u32>,
    pub start: Option<String>,
    pub end: Option<String>,
    pub level: Option<LogLevel>,
}

pub trait LogsRead {
    fn get_logs(
        &self,
        options: LogsOptions,
    ) -> impl Future<Output = Result<Vec<LogLine>>> + Send + '_;
}

pub async fn get_logs<C: LogsRead + ?Sized>(
    client: &C,
    options: LogsOptions,
) -> Result<Vec<LogLine>> {
    client.get_logs(options).await
}
