use std::sync::{
	RwLock,
	atomic::AtomicBool
};
use crate::engine::rule::RuleFile;

pub static SELECTED_RULES: RwLock<Vec<RuleFile>> = RwLock::new(Vec::new());
pub static STOP_CRAWL: AtomicBool = AtomicBool::new(false);
