use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use attackstr::{Payload, PayloadDb};
use colored::Colorize;
use futures::stream::FuturesUnordered;
use futures::StreamExt;
use reqwest::Client;
use tokio::sync::Semaphore;
use tokio::time::interval;
use url::Url;
use wafrift_oracle::ssrf::SsrfOracle;
use wafrift_oracle::traits::PayloadOracle;

#[derive(Debug, Clone)]
pub enum SsrfType {
    Classic,
    Blind,
    TimeBased,
    Potential,
}

#[derive(Debug)]
pub struct ScanResult {
    payload: String,
    final_url: String,
    status_code: Option<u16>,
    error: Option<String>,
    elapsed: Duration,
    ssrf_type: SsrfType,
    evidence: String,
    confidence: u8,
    is_vulnerable: bool,
}

// ------------------------------------------------------------
// توابع کمکی کوچک
// ------------------------------------------------------------

fn build_http_client(timeout_secs: u64) -> Result<Client, Box<dyn std::error::Error>> {
    Ok(Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(timeout_secs))
        .build()?)
}

async fn measure_baseline(client: &Client, target: &str) -> Duration {
    let start = Instant::now();
    let _ = client.get(target).send().await;
    start.elapsed()
}

async fn load_ssrf_payloads(grammars_path: &Path) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let mut db = PayloadDb::new();
    if !grammars_path.exists() {
        return Err(format!("Grammar directory not found: {}", grammars_path.display()).into());
    }
    db.load_dir(grammars_path)?;
    let payloads: Vec<String> = db
        .payloads("ssrf")
        .into_iter()
        .map(|p| p.text)
        .collect();
    if payloads.is_empty() {
        return Err("No SSRF payloads found in grammars".into());
    }
    Ok(payloads)
}

fn filter_payloads_with_oracle(payloads: Vec<String>) -> Vec<String> {
    let oracle = SsrfOracle;
    payloads
        .into_iter()
        .filter(|p| oracle.is_semantically_valid("http://127.0.0.1/", p))
        .collect()
}

fn inject_payload(base_url: &str, payload: &str) -> String {
    let mut url = match Url::parse(base_url) {
        Ok(u) => u,
        Err(_) => {
            let base = base_url.trim_end_matches('/');
            return format!("{}/{}", base, payload.trim_start_matches('/'));
        }
    };
    let target_params = ["url", "dest", "redirect", "next", "return_to", "out", "path"];
    if url.query().is_none() {
        for param in target_params.iter() {
            url.query_pairs_mut().append_pair(param, payload);
        }
    } else {
        let mut pairs: Vec<(String, String)> = url
            .query_pairs()
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();
        for (k, v) in pairs.iter_mut() {
            if target_params.contains(&k.as_str()) {
                *v = payload.to_string();
            }
        }
        url.query_pairs_mut().clear();
        for (k, v) in pairs {
            url.query_pairs_mut().append_pair(&k, &v);
        }
    }
    url.to_string()
}

async fn scan_enhanced(
    client: &Client,
    target_url: &str,
    payload_text: String,
    baseline: Duration,
) -> ScanResult {
    let final_url = inject_payload(target_url, &payload_text);
    let test_start = Instant::now();
    let response = client.get(&final_url).send().await;
    let elapsed = test_start.elapsed();

    match response {
        Ok(res) => {
            let status = res.status().as_u16();
            let body = res.text().await.unwrap_or_default().to_lowercase();
            let has_leak = body.contains("instance-id")
                || body.contains("ami-id")
                || body.contains("secret")
                || body.contains("root:x:")
                || body.contains("aws_session")
                || body.contains("access_key");
            let is_time_suspicious = elapsed > baseline * 3;
            let (ssrf_type, confidence, evidence) = if has_leak {
                (SsrfType::Classic, 90, "Data leak detected in response".to_string())
            } else if is_time_suspicious {
                (
                    SsrfType::TimeBased,
                    55,
                    format!("Delay {:?} > 3x baseline {:?}", elapsed, baseline),
                )
            } else {
                (SsrfType::Potential, 20, "No strong indicators".to_string())
            };
            ScanResult {
                payload: payload_text,
                final_url,
                status_code: Some(status),
                error: None,
                elapsed,
                ssrf_type,
                evidence,
                confidence,
                is_vulnerable: has_leak || is_time_suspicious,
            }
        }
        Err(e) => {
            let is_timeout = e.is_timeout();
            let evidence = if is_timeout {
                "Timeout - possible firewall or internal service".to_string()
            } else {
                e.to_string()
            };
            ScanResult {
                payload: payload_text,
                final_url,
                status_code: None,
                error: Some(e.to_string()),
                elapsed,
                ssrf_type: if is_timeout { SsrfType::Blind } else { SsrfType::Potential },
                evidence,
                confidence: if is_timeout { 50 } else { 10 },
                is_vulnerable: is_timeout,
            }
        }
    }
}

async fn run_throttled_scan(
    client: Arc<Client>,
    target: String,
    payloads: Vec<String>,
    baseline: Duration,
    max_concurrent: usize,
    delay_between_starts: Duration,
) -> Vec<ScanResult> {
    let semaphore = Arc::new(Semaphore::new(max_concurrent));
    let mut interval = interval(delay_between_starts);
    interval.tick().await; // اولین درخواست بی‌درنگ

    let mut tasks = FuturesUnordered::new();
    let mut payload_iter = payloads.into_iter();

    loop {
        interval.tick().await;
        let Some(payload) = payload_iter.next() else { break };
        let permit = semaphore.clone().acquire_owned().await.unwrap();
        let client_clone = client.clone();
        let target_clone = target.clone();
        tasks.push(async move {
            let result = scan_enhanced(&client_clone, &target_clone, payload, baseline).await;
            drop(permit);
            result
        });
    }

    let mut results = Vec::with_capacity(tasks.len());
    while let Some(r) = tasks.next().await {
        results.push(r);
    }
    results
}

fn print_scan_results(results: &[ScanResult]) {
    let mut vuln_count = 0;
    for r in results {
        if r.is_vulnerable {
            vuln_count += 1;
            println!("{} {}", "[VULN] 🚨".red().bold(), r.final_url.red());
            println!(
                "  {} Type: {:?}, Confidence: {}%, Status: {:?}, Took: {:?}",
                "↳".yellow(),
                r.ssrf_type,
                r.confidence,
                r.status_code,
                r.elapsed
            );
            println!("  {} Evidence: {}", "↳".yellow(), r.evidence.yellow());
        } else {
            println!(
                "{} {} (Status: {:?}, Time: {:?})",
                "[OK] ✅".green(),
                r.final_url.dimmed(),
                r.status_code,
                r.elapsed
            );
        }
    }
    println!("\n{} Finished scanning.", "[✓]".green().bold());
    println!(
        "   Tested {} payloads | Found {} potential vulnerabilities.",
        results.len(),
        vuln_count
    );
}

// ------------------------------------------------------------
// تابع اصلی run
// ------------------------------------------------------------
pub async fn run(target_url: &str) -> Result<(), Box<dyn std::error::Error>> {
    const TIMEOUT_SECS: u64 = 5;
    const MAX_CONCURRENT: usize = 10;
    const DELAY_MS: u64 = 800;

    let client = build_http_client(TIMEOUT_SECS)?;
    let baseline = measure_baseline(&client, target_url).await;
    println!("⏱️ Baseline Response Time: {:?}", baseline);

    let grammars_path = Path::new("./grammars");
    let raw_payloads = load_ssrf_payloads(grammars_path).await?;
    println!(
        "{} Generated {} raw SSRF payloads.",
        "[✓]".green().bold(),
        raw_payloads.len()
    );

    let valid_payloads = filter_payloads_with_oracle(raw_payloads);
    println!(
        "{} Filtered {} semantically valid payloads.",
        "[✓]".green().bold(),
        valid_payloads.len()
    );
    println!(
        "⚡ Starting scan: concurrency={}, delay={}ms between starts",
        MAX_CONCURRENT, DELAY_MS
    );

    let client_arc = Arc::new(client);
    let results = run_throttled_scan(
        client_arc,
        target_url.to_string(),
        valid_payloads,
        baseline,
        MAX_CONCURRENT,
        Duration::from_millis(DELAY_MS),
    )
    .await;

    print_scan_results(&results);
    Ok(())
}
