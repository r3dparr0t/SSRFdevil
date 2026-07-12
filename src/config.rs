// config.rs
use std::sync::{OnceLock, RwLock};
use std::collections::HashMap;

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
    // --- تنظیمات عمومی و اسکنر ---
    pub ua_profile: UaProfile,
    pub custom_headers: HashMap<String, String>,
    //pub timeout: i32,
    pub threads: i32,
    pub delay_min: u64,
    pub delay_max: u64,
    //pub redirects: usize,
    pub max_runtime: u64,
    
    // --- تنظیمات اختصاصی خزنده (جدید) ---
    pub crawler_proxies: Vec<String>,
    pub crawler_proxy_rotation: bool,
    pub crawler_rate_limit: usize,
    pub crawler_max_depth: usize,
    
    // --- تنظیمات کیلسوییچ و وضعیت (جدید) ---
    pub crawler_max_targets: usize,
    pub crawler_save_state: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            ua_profile: UaProfile::Balanced,
            custom_headers: HashMap::new(),
           
            //timeout: 5,
            threads: 10, // این همون مقدار ماکسیمم همزمانی (Worker Count) خواهد بود
            delay_min: 1000, // پیش‌فرض ۱ ثانیه
            delay_max: 3500, // پیش‌فرض ۳.۵ ثانیه
            //redirects: 3,
            max_runtime: 0,  // 0 یعنی نامحدود
          
            crawler_proxies: Vec::new(),
            crawler_proxy_rotation: false,
            crawler_rate_limit: 0,   // 0 یعنی نامحدود
            crawler_max_depth: 3,
            crawler_max_targets: 0,  // 0 یعنی نامحدود
            crawler_save_state: false,
        }
    }
}

// تعریف تک‌نسخه‌ای و استاتیک از تنظیمات کل پروژه
pub static APP_SETTINGS: OnceLock<RwLock<Settings>> = OnceLock::new();

// یک تابع کمکی برای دسترسی راحت‌تر به تنظیمات در سراسر پروژه
pub fn init_global_settings() {
    APP_SETTINGS.get_or_init(|| RwLock::new(Settings::default()));
}
