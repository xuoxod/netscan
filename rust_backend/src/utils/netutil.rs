use std::fs;
use std::io::{self, Write};
use std::path::Path;
use std::time::{Duration, SystemTime};

/// Checks if the system has internet access by connecting to a well-known site.
pub fn has_internet() -> Result<bool, String> {
    let test_url = "https://www.google.com/generate_204";
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(3))
        .build()
        .map_err(|e| format!("Failed to build HTTP client: {e}"))?;
    match client.get(test_url).send() {
        Ok(resp) if resp.status().is_success() => Ok(true),
        Ok(resp) => Err(format!(
            "Internet check failed: HTTP status {}. Try checking your proxy or firewall.",
            resp.status()
        )),
        Err(e) => Err(format!(
            "Internet check failed: {e}. Are you connected to the internet?"
        )),
    }
}

/// Fetches a file from the web and caches it locally.
/// If the cache is fresh (default 7 days), uses the cached file.
pub fn fetch_and_cache(url: &str, cache_path: &str, max_age_days: u64) -> Result<(), String> {
    let path = Path::new(cache_path);
    let cache_fresh = path.exists() && path.metadata().and_then(|m| m.modified()).map_or(false, |mtime| {
        mtime.elapsed().map_or(false, |elapsed| elapsed.as_secs() < max_age_days * 86400)
    });

    if cache_fresh {
        return Ok(());
    }

    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|e| format!("Failed to build HTTP client: {e}"))?;

    let resp = client.get(url).send()
        .map_err(|e| format!("Failed to fetch {url}: {e}. Check your internet connection."))?;

    if !resp.status().is_success() {
        return Err(format!(
            "Failed to fetch {url}: HTTP status {}. Try again later.",
            resp.status()
        ));
    }

    let bytes = resp.bytes()
        .map_err(|e| format!("Failed to read response body: {e}"))?;

    fs::write(path, &bytes)
        .map_err(|e| format!("Failed to write to cache file {cache_path}: {e}"))?;

    Ok(())
}