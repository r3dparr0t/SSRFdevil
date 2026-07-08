//config.rs
use std::sync::{OnceLock, RwLock};

#[derive(Debug, Clone, PartialEq)]
pub enum UaProfile {
    Conservative, 
    Balanced,     
    Full,         
}

impl UaProfile {
    pub fn min_weight(&self) -> u32 {
        match self {
            UaProfile::Conservative => 70,
            UaProfile::Balanced => 30,
            UaProfile::Full => 0,
        }
    }

    pub fn label(&self) -> &str {
        match self {
            UaProfile::Conservative => "conservative (weight >= 70)",
            UaProfile::Balanced => "balanced     (weight >= 30)",
            UaProfile::Full => "full         (all agents)",
        }
    }
}

pub struct Settings {
    pub ua_profile: UaProfile,
    pub timeout: i32,
    pub threads: i32,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            ua_profile: UaProfile::Balanced,
            timeout: 5,
            threads: 10,
        }
    }
}


// همان امضاها و تعاریف قبلی Settings و UaProfile اینجا می‌مانند...

// تعریف تک‌نسخه‌ای و استاتیک از تنظیمات کل پروژه
pub static APP_SETTINGS: OnceLock<RwLock<Settings>> = OnceLock::new();

// یک تابع کمکی برای دسترسی راحت‌تر به تنظیمات در سراسر پروژه
pub fn init_global_settings() {
    APP_SETTINGS.get_or_init(|| RwLock::new(Settings::default()));
}

