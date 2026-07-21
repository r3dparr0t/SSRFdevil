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
            .filter(|t| is_match(t, &rule.r#match))
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
    // ۱. بررسی TargetKind
    if target.kind == TargetKind::Resource {
        return false;
    }

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

    // ۳. بررسی Tags (مقایسه تگ‌های TargetTag با required_tags موجود در YAML)
    if !matcher.required_tags.is_empty() {
        let has_matching_tag = matcher.required_tags.iter().any(|req_tag| {
            target
                .meta
                .tags
                .iter()
                .any(|target_tag| target_tag.as_str().eq_ignore_ascii_case(req_tag))
        });

        if !has_matching_tag {
            return false;
        }
    }

    // ۴. بررسی وجود پارامتر
    if matcher.require_params && target.params.is_empty() {
        return false;
    }

    true
}
