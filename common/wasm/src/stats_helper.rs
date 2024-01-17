use std::fmt::Display;

use serde::{Deserialize, Serialize};
use typescript_type_def::TypeDef;

/// Compute the mean an variance of a series of samples using
/// Welford's algorithm (which is an online algorithm that's numerically
/// stable). See https://en.wikipedia.org/wiki/Algorithms_for_calculating_variance#Welford's_online_algorithm
/// Also tracks min and max observed values
#[derive(Clone, Debug, Default, PartialEq)]
pub struct SimpleStats {
    num_samples: usize,
    mean: f64,
    m2: f64,
    min: f64,
    max: f64,
}

impl SimpleStats {
    pub fn new() -> Self {
        Default::default()
    }

    /// Add a new sample value
    pub fn add_sample(&mut self, sample: f64) {
        if self.num_samples == 0 {
            self.min = sample;
            self.max = sample;
        } else {
            self.min = self.min.min(sample);
            self.max = self.max.max(sample);
        }
        self.num_samples += 1;
        let delta = sample - self.mean;
        self.mean += delta / self.num_samples as f64;
        let delta2 = sample - self.mean;
        self.m2 += delta * delta2;
    }

    /// returns the mean of the samples
    pub fn mean(&self) -> f64 {
        self.mean
    }

    /// returns the variance of the samples
    pub fn variance(&self) -> Option<f64> {
        if self.num_samples < 2 {
            None
        } else {
            Some(self.m2 / (self.num_samples - 1) as f64)
        }
    }

    /// returns the number of samples
    pub fn num_samples(&self) -> usize {
        self.num_samples
    }

    pub fn max(&self) -> f64 {
        self.max
    }

    pub fn min(&self) -> f64 {
        self.min
    }
}

impl Display for SimpleStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "[n={} mean={}, var={}, min={}, max={}]",
            self.num_samples,
            self.mean(),
            self.variance().map_or("None".to_owned(), |v| v.to_string()),
            self.min,
            self.max
        )
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, TypeDef)]
pub struct ExportedSimpleStats {
    num_samples: usize,
    mean: f64,
    variance: Option<f64>,
    min: f64,
    max: f64,
}

impl From<SimpleStats> for ExportedSimpleStats {
    fn from(s: SimpleStats) -> Self {
        Self {
            num_samples: s.num_samples,
            mean: s.mean,
            variance: s.variance(),
            min: s.min,
            max: s.max,
        }
    }
}

impl Display for ExportedSimpleStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "[n={} mean={}, var={}, min={}, max={}]",
            self.num_samples,
            self.mean,
            self.variance.map_or("None".to_owned(), |v| v.to_string()),
            self.min,
            self.max
        )
    }
}

impl ExportedSimpleStats {
    /// returns the mean of the samples
    pub fn mean(&self) -> f64 {
        self.mean
    }

    /// returns the variance of the samples
    pub fn variance(&self) -> Option<f64> {
        self.variance
    }

    /// returns the number of samples
    pub fn num_samples(&self) -> usize {
        self.num_samples
    }

    pub fn max(&self) -> f64 {
        self.max
    }

    pub fn min(&self) -> f64 {
        self.min
    }
}

#[cfg(test)]
mod test {
    use approx::assert_relative_eq;

    use super::*;

    #[test]
    fn test_simple_stats() {
        let mut stats = SimpleStats::new();
        stats.add_sample(4.);
        stats.add_sample(6.);
        assert_eq!(stats.mean(), 5.0);
        assert_eq!(stats.variance().unwrap(), 2.0);
        assert_eq!(stats.num_samples(), 2);
        stats.add_sample(10.);
        stats.add_sample(11.);
        stats.add_sample(7.);
        stats.add_sample(9.);
        assert_relative_eq!(stats.mean(), 7.833333, epsilon = 1e-5);
        assert_relative_eq!(stats.variance().unwrap(), 6.9666667, epsilon = 1e-5);
        assert_eq!(stats.num_samples(), 6);
        assert_eq!(stats.min(), 4.0);
        assert_eq!(stats.max(), 11.0);

        let exported_stats: ExportedSimpleStats = stats.clone().into();
        assert_eq!(exported_stats.num_samples(), stats.num_samples());
        assert_eq!(exported_stats.mean(), stats.mean());
        assert_eq!(exported_stats.variance(), stats.variance());
        assert_eq!(exported_stats.min(), stats.min());
        assert_eq!(exported_stats.max(), stats.max());

        let mut stats = SimpleStats::new();
        assert_eq!(stats.mean(), 0.0);
        assert_eq!(stats.variance(), None);
        assert_eq!(stats.num_samples(), 0);
        assert_eq!(stats.min(), 0.0);
        assert_eq!(stats.max(), 0.0);
        stats.add_sample(123.456);
        assert_eq!(stats.mean(), 123.456);
        assert_eq!(stats.variance(), None);
        assert_eq!(stats.num_samples(), 1);
        assert_eq!(stats.min(), 123.456);
        assert_eq!(stats.max(), 123.456);
    }
}
