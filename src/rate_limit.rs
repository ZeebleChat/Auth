use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Simple in-memory sliding-window rate limiter keyed by an arbitrary string (e.g. client IP).
/// Thread-safe via an internal Mutex.
pub struct RateLimiter {
    state: Mutex<HashMap<String, (u32, Instant)>>,
    limit: u32,
    window: Duration,
}

impl RateLimiter {
    pub fn new(limit: u32, window_secs: u64) -> Self {
        Self {
            state: Mutex::new(HashMap::new()),
            limit,
            window: Duration::from_secs(window_secs),
        }
    }

    /// Returns `true` if the request is allowed, `false` if the limit is exceeded.
    pub fn check(&self, key: &str) -> bool {
        let mut map = self.state.lock().unwrap_or_else(|e| {
            eprintln!("WARNING: rate limiter mutex was poisoned; recovering — state may be inconsistent");
            e.into_inner()
        });
        let now = Instant::now();
        let entry = map.entry(key.to_string()).or_insert((0, now));
        if now.duration_since(entry.1) >= self.window {
            // Window expired — reset counter.
            *entry = (1, now);
            true
        } else if entry.0 < self.limit {
            entry.0 += 1;
            true
        } else {
            false
        }
    }
}
