use serde::{Deserialize, Serialize};
use crate::crawler::crawler_config::TargetKind;

// زیرمجموعه برای بخش تطبیق پروتکل‌ها
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct MatchConfig {
    #[serde(default)]
    pub schemes: Vec<String>,
    #[serde(default)]
    pub requires: Vec<String>,
    #[serde(default)]
    pub supports: Vec<String>,
    #[serde(default)]
    pub kinds: Vec<TargetKind>,
    #[serde(default)]
    pub required_tags: Vec<String>,
    #[serde(default)]
    pub require_params: bool,
}

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Serialize,
    Deserialize,
)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub const fn weight(self) -> u8 {
        match self {
            Self::Info => 0,
            Self::Low => 1,
            Self::Medium => 2,
            Self::High => 3,
            Self::Critical => 4,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// زیرمجموعه برای بخش اسکریپت داینامیک
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ScriptConfig {
    pub language: String,
    pub entry: String,
    pub source: String,
}

// ۱. ساختار جدید متادیتای رول با تمام فیلدهای شیک چت‌جی‌پتی
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RuleMeta {
    pub id: String,
    pub version: u32,
    pub name: String,
    pub description: String,
    pub author: String,
    pub created: String,
    pub updated: String,
    pub rank: u32,
    pub confidence: u8,
    pub severity: Severity,
    pub tags: Vec<String>,
    pub references: Vec<String>,
    #[serde(default)]
    pub success_indicator: Vec<String>,   // literal: / regex:
    #[serde(default)]
    pub failure_indicator: Vec<String>,   // literal: / regex:
}

// ۲. ساختار کامل فایل جدید YAML
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RuleFile {
    pub meta: RuleMeta,
    pub r#match: MatchConfig,
    pub script: ScriptConfig,
}

#[derive(Debug, Clone)]
pub struct RuleTrace {
    pub rule_id: String,
    pub matched: bool,
    pub input: String,
    pub output: Option<String>,
    pub steps: Vec<TraceStep>,
}

#[derive(Debug, Clone)]
pub struct TraceStep {
    pub stage: String,     // match / script / transform
    pub message: String,
}
pub enum RuleCategory {
    CloudMetadata, // تست‌های AWS, GCP, Azure
    InternalInfra,  // تست‌های کانتینرها، داکر، کوبرنتیز
    GenericWebhook, // تست‌های وب‌هوک و پورت‌های داخلی
}

pub fn explain_trace(trace: &RuleTrace) {
    println!("\n=== Rule Execution Trace ===\nRule: {}\nInput: {}"
	, trace.rule_id, trace.input);
    for step in &trace.steps {
        println!("[{}] {}", step.stage, step.message);
    }
    println!("Output: {:?}", trace.output);
}
