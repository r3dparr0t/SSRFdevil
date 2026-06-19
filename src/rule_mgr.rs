use sled::{Db, Batch, IVec};
use serde::{Deserialize, Serialize};
use std::{fs, error::Error};

// زیرمجموعه برای بخش تطبیق پروتکل‌ها
#[derive(Debug, Serialize, Deserialize)]
pub struct MatchConfig {
    #[serde(default)]
    pub schemes: Vec<String>,
    #[serde(default)]
    pub requires: Vec<String>,
    #[serde(default)]
    pub supports: Vec<String>,
}

// زیرمجموعه برای بخش اسکریپت داینامیک
#[derive(Debug, Serialize, Deserialize)]
pub struct ScriptConfig {
    pub language: String,
    pub entry: String,
    pub source: String,
}

// ۱. ساختار جدید متادیتای رول با تمام فیلدهای شیک چت‌جی‌پتی
#[derive(Debug, Serialize, Deserialize)]
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
#[derive(Debug, Serialize, Deserialize)]
pub struct RuleFile {
    pub meta: RuleMeta,
    pub r#match: MatchConfig,
    pub script: ScriptConfig,
}

// توابع populate_rules_db و get_default_rule و list_rules قبلی 
// به خاطر ساختار منعطف serde و sled بدون دستکاری به کار خودشان ادامه می‌دهند!


// اضافه شدن pub به تابع
pub fn populate_rules_db(db: &Db, rules_path: &str) -> Result<(), Box<dyn Error>> {
    let mut batch = Batch::default();

    let entries = fs::read_dir(rules_path)?
        .filter_map(|res| res.ok())
        .map(|e| e.path())
        .filter(|path| path.is_file())
        .filter(|path| {
            path.extension()
                .map(|ext| ext == "yaml" || ext == "yml")
                .unwrap_or(false)
        });

    for path in entries {
        if let Ok(content) = fs::read_to_string(&path) {
            match serde_yaml::from_str::<RuleFile>(&content) {
                Ok(rule) => {
                    let key = rule.meta.name.as_bytes();
                    if let Ok(value_bytes) = serde_json::to_vec(&rule)
                    {
                        batch.insert(key, value_bytes);
                    }
                    println!("Loaded rule: {} (Rank: {})", rule.meta.name, rule.meta.rank);
                }
                Err(e) => {
                    println!("YAML Error in {:?}\n{}", path, e);
                }
            }
        }
    }

    db.apply_batch(batch)?;
    println!("Rules synthesized successfully!");
    Ok(())
}

// اضافه شدن pub و اصلاح تایپ‌های درون کلوژر برای رفع خطای E0277
pub fn get_default_rule(db: &Db) -> Option<RuleFile> {
    let mut all_rules: Vec<RuleFile> = db
        .iter()
        .filter_map(|res| res.ok()) 
        .filter_map(|(_, value): (IVec, IVec)| { // مشخص کردن دقیق تایپ به صورت IVec
            serde_json::from_slice::<RuleFile>(&value).ok()
        })
        .collect();

    all_rules.sort_by(|a, b| {
        let rank_cmp = b.meta.rank.cmp(&a.meta.rank);
        if rank_cmp == std::cmp::Ordering::Equal {
            b.meta.updated.cmp(&a.meta.updated)
        } else {
            rank_cmp
        }
    });

    all_rules.into_iter().next()
}

// اضافه شدن pub
pub fn get_rule_by_name(db: &Db, name: &str) -> Option<RuleFile> {
    if let Ok(Some(value)) = db.get(name.as_bytes()) {
        serde_json::from_slice::<RuleFile>(&value).ok()
    } else {
        None
    }
}

// اضافه شدن pub و اصلاح کلوژر
pub fn list_rules(db: &Db) {
    let mut all_rules: Vec<RuleFile> = db
        .iter()
        .filter_map(|res| res.ok())
        .filter_map(|(_, value): (IVec, IVec)| serde_json::from_slice::<RuleFile>(&value).ok())
        .collect();

    all_rules.sort_by(|a, b| b.meta.rank.cmp(&a.meta.rank));

    println!("\n=== Available SSRFdevil Rules ===");
    for rule in all_rules {
        show_rule(&rule);
    }
    println!("=================================\n");
}

fn show_rule(rule: &RuleFile) {
    println!(
        "-> Name:        {}\n   Updated:        {}\n   Rank:        {}\n   Description: {}\n",
        rule.meta.name, rule.meta.updated, rule.meta.rank, rule.meta.description
    );
}
