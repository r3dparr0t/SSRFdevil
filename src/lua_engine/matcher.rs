use crate::{
    crawler::crawler_config::{Target, TargetKind},
    engine::rule::{MatchConfig, RuleFile},
};

pub struct BatchTask<'a> {
    pub rule: &'a RuleFile,
    pub targets: Vec<&'a Target>,
}

pub fn create_batches<'a>(targets: &'a [Target], rules: &'a [RuleFile]) -> Vec<BatchTask<'a>> {
    let mut tasks = Vec::new();

    for rule in rules {
        let matched_targets: Vec<&Target> = targets
            .iter()
            .filter(|t| is_match(t, &rule.r#match)) // اصلاح نام فیلد
            .collect();

        if !matched_targets.is_empty() {
            tasks.push(BatchTask {
                rule,
                targets: matched_targets,
            });
        }
    }

    tasks
}

fn is_match(target: &Target, matcher: &MatchConfig) -> bool {
    // ۱. بررسی TargetKind (مثلا نادیده گرفتن Resource ها)
    if target.kind == TargetKind::Resource {
        return false;
    }

    // اگر kinds مشخص شده بود و target شاملش نبود
    if !matcher.kinds.is_empty() && !matcher.kinds.contains(&target.kind) {
        return false;
    }

    // ۲. بررسی Scheme
    if !matcher.schemes.is_empty() {
        let target_scheme = target.url.scheme().to_string();
        if !matcher.schemes.contains(&target_scheme) {
            return false;
        }
    }

    // ۳. بررسی Tags (اگر رول نیاز به تگ‌های خاصی داشت)
    /* if !matcher.required_tags.is_empty() {
        let has_matching_tag = matcher
            .required_tags
            .iter()
            .any(|tag| target.meta.tags.contains(tag));
            
        if !has_matching_tag {
            return false;
        }
    }*/
    if !matcher.required_tags.is_empty() {
        let has_matching_tag = matcher.required_tags.iter().any(|req_tag| {
            target.meta.tags.iter().any(|t| t.as_str().eq_ignore_ascii_case(req_tag))
        });
            
        if !has_matching_tag {
            return false;
        }
    }

    // ۴. بررسی وجود پارامتر در صورت نیاز رول
    if matcher.require_params && target.params.is_empty() {
        return false;
    }
    true
}
