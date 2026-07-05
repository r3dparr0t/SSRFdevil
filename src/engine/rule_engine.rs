use sled::{Batch, Db, IVec};
//use serde::{Deserialize, Serialize};
use std::{
    sync::RwLock,
    {error::Error, fs}
};

use crate::rule::RuleFile;

pub static SELECTED_RULES: RwLock<Vec<RuleFile>> = RwLock::new(Vec::new());

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
                    let key = rule.meta.id.as_bytes();
                    if let Ok(value_bytes) = serde_json::to_vec(&rule) {
                        batch.insert(key, value_bytes);
                    }
                    //println!("Loaded rule: {} (Rank: {})", rule.meta.name, rule.meta.rank);
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

pub fn get_default_rule(db: &Db) -> Option<RuleFile> {
    let mut all_rules: Vec<RuleFile> = db
        .iter()
        .filter_map(|res| res.ok())
        .filter_map(|(_, value): (IVec, IVec)| {
            // مشخص کردن دقیق تایپ به صورت IVec
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

/*pub fn get_rule_by_id(db: &Db, id: &str) -> Option<RuleFile> {
    if let Ok(Some(value)) = db.get(id.as_bytes()) {
        serde_json::from_slice::<RuleFile>(&value).ok()
    } else {
        None
    }
}*/
pub fn get_rule_by_id(db: &Db, id: &str) -> Option<RuleFile> {
    db.get(id.as_bytes())
        .ok()
        .flatten()
        .and_then(|value| serde_json::from_slice::<RuleFile>(&value).ok())
}

pub fn search_rules(db: &Db, query: &str) -> Vec<RuleFile> {
    let q = query.to_lowercase();

    let mut rules: Vec<RuleFile> = db
        .iter()
        .filter_map(|r| r.ok())
        .filter_map(|(_, value)| serde_json::from_slice::<RuleFile>(&value).ok())
        .filter(|rule| {
            if q.is_empty() {
                return true;
            }

            rule.meta.id.to_lowercase().contains(&q)
                || rule.meta.name.to_lowercase().contains(&q)
                || rule.meta.description.to_lowercase().contains(&q)
                || rule.meta.tags.iter().any(|t| t.to_lowercase().contains(&q))
        })
        .collect();

    rules.sort_by(|a, b| b.meta.rank.cmp(&a.meta.rank));

    rules
}

pub fn display_rule(i: i32, rule: &RuleFile) {
    println!(
        "{:<4} {:<6} {:<28} {}",
        i, rule.meta.rank, rule.meta.id, rule.meta.name
    );
}

pub fn display_result_rules(results: &[RuleFile]) {
    if results.is_empty() {
        println!("\n[!] No matching rules found.\n");
        return;
    }
    println!("\n{:<4} {:<6} {:<28} {}", "#", "Rank", "ID", "Name");

    for (i, rule) in results.iter().enumerate() {
        display_rule(i.try_into().unwrap(), rule);
    }
    println!();
}
pub fn show_rule_details(rule: &RuleFile) {
    println!();
    println!("ID          : {}", rule.meta.id);
    println!("Name        : {}", rule.meta.name);
    println!("Version     : {}", rule.meta.version);
    println!("Rank        : {}", rule.meta.rank);
    println!("Confidence  : {}", rule.meta.confidence);
    println!("Severity    : {}", rule.meta.severity);

    println!();
    println!("Description:");
    println!("{}", rule.meta.description);

    println!();
    println!("Tags:");

    if rule.meta.tags.is_empty() {
        println!("(none)");
    } else {
        println!("{}", rule.meta.tags.join(", "));
    }

    println!();
}
