use tokio::time::{Duration, Instant};

#[derive(Clone, Debug, PartialEq, Eq)]
/// A very simple rate limiter, that uses a fixed time window between events.
/// I.e., no bursts or anything.
pub struct SimpleRateLimiter {
    time_between_events: Duration,
    last_event_time: Instant,
}

impl SimpleRateLimiter {
    /// Create a new rate limiter that allows one event per `time_window`.
    pub fn new(time_between_events: Duration) -> Self {
        Self {
            time_between_events,
            last_event_time: Instant::now() - time_between_events,
        }
    }

    pub fn check_update(&mut self) -> bool {
        if self.last_event_time.elapsed() >= self.time_between_events {
            self.last_event_time = Instant::now();
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[tokio::test]
    pub async fn test_simple_rate_limiter() {
        let mut srl = SimpleRateLimiter::new(Duration::from_millis(500));
        assert_eq!(srl.time_between_events, Duration::from_millis(500));
        assert_eq!(srl.check_update(), true);
        assert_eq!(srl.check_update(), false);
        tokio::time::pause();
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(srl.check_update(), false);
        tokio::time::sleep(Duration::from_millis(210)).await;
        assert_eq!(srl.check_update(), true);
        tokio::time::sleep(Duration::from_millis(5000)).await;
        assert_eq!(srl.check_update(), true);
        tokio::time::resume();
        assert_eq!(srl.check_update(), false);
    }
}
