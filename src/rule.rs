use serde::{Deserialize, Serialize};

// زیرمجموعه برای بخش تطبیق پروتکل‌ها
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct MatchConfig {
    #[serde(default)]
    pub schemes: Vec<String>,
    #[serde(default)]
    pub requires: Vec<String>,
    #[serde(default)]
    pub supports: Vec<String>,
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
    pub confidence: u32,
    pub severity: String,
    pub tags: Vec<String>,
    pub references: Vec<String>,
}

// ۲. ساختار کامل فایل جدید YAML
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RuleFile {
    pub meta: RuleMeta,
    pub r#match: MatchConfig,
    pub script: ScriptConfig,
}
