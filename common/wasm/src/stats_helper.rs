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

/// A simple implementation of percentiles. It takes an array of integer values,
/// sorts them, and can then return percentiles.
pub struct NaiivePercentiles {
    values: Vec<u64>,
}

impl NaiivePercentiles {
    /// Create a new instance over the given values.
    pub fn new(mut values: Vec<u64>) -> Self {
        values.sort();
        Self { values }
    }

    /// Return the given percentile value. Percentile must be <= 100.
    /// IMPORTANT NOTE: We use integer arithmetic. For some percentiles we need to
    /// compute `(x[i] + x[i+1]) / 2` (cf. median of a set with even number of elements).
    /// This will be an *integer* division so if the values are small, we get a truncation error
    /// `P0` is the min value, `P100` is the max value.
    /// If values is empty, will always return None. If there is at least one value, will return
    /// Some(x)
    ///
    /// Note, this function will either return an original sample value, or the mean of two
    /// neighboring values, depending on the index calculation. So, if the number of samples
    /// is small, it will return discontinous results (thus naiive)
    ///
    /// This implemention matches the logic of `numpy.percentile()`'s `averaged_inverted_cdf`
    /// method. https://numpy.org/doc/stable/reference/generated/numpy.percentile.html
    pub fn percentile(&self, percentile: u8) -> Option<u64> {
        assert!(
            percentile <= 100,
            "Percentile must be <= 100, was {}",
            percentile
        );
        let index = (percentile as usize * self.values.len()) / 100;
        let index_rem = (percentile as usize * self.values.len()) % 100;
        if self.values.is_empty() {
            return None;
        }
        if index == 0 {
            return Some(self.values[0]);
        }
        if index >= self.values.len() {
            // we have at least one element, so unwrap is safe
            return Some(*self.values.last().unwrap());
        }
        // We are now guaranteed that we have at least 1 element in the vec and
        // that 0 < index < self.values.len(). Therefor we are guaranteed that
        // values[index] and values[index-1] are valid entries.
        if index_rem == 0 {
            // No remainder. E.g, with 4 elements and P50:
            // index = 4*50 / 100 = 2; remainder = 0. return (x[1] + x[2])/2 which is the median
            Some((self.values[index - 1] + self.values[index]) / 2)
        } else {
            // We have a remainder. Round down (i.e., just take the index).
            // E.g., with 5 values and P50: index = 5 * 50 / 100 = 2; remainder = 50 ==> index = 2
            Some(self.values[index])
        }
    }
}

#[cfg(test)]
mod test {
    use approx::assert_relative_eq;
    use itertools::Itertools;

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

    #[test]
    #[should_panic]
    fn test_invalid_percentile() {
        let p = NaiivePercentiles::new((1..200).collect());
        p.percentile(101);
    }

    #[test]
    fn test_naiive_percentiles() {
        let p = NaiivePercentiles::new(vec![10, 20, 30, 40, 50]);
        assert_eq!(p.percentile(0).unwrap(), 10);
        assert_eq!(p.percentile(100).unwrap(), 50);
        // Odd number of elements. ==> P50 is the middle element
        assert_eq!(p.percentile(50).unwrap(), 30);
        assert_eq!(p.percentile(90).unwrap(), 50);

        let p = NaiivePercentiles::new(vec![10, 20, 30, 40, 50, 60]);
        assert_eq!(p.percentile(0).unwrap(), 10);
        assert_eq!(p.percentile(100).unwrap(), 60);
        // Even number of elements. ==> P50 mean of the two middle elements
        assert_eq!(p.percentile(50).unwrap(), 35);
        assert_eq!(p.percentile(90).unwrap(), 60);
        assert_eq!(p.percentile(10).unwrap(), 10);

        // same range as before, but in different order
        let p = NaiivePercentiles::new(vec![60, 20, 40, 10, 30, 50]);
        assert_eq!(p.percentile(0).unwrap(), 10);
        assert_eq!(p.percentile(100).unwrap(), 60);
        // Even number of elements. ==> P50 mean of the two middle elements
        assert_eq!(p.percentile(50).unwrap(), 35);
        assert_eq!(p.percentile(90).unwrap(), 60);
        assert_eq!(p.percentile(10).unwrap(), 10);

        // Test empty samples
        let p = NaiivePercentiles::new(Vec::new());
        assert_eq!(p.percentile(0), None);
        assert_eq!(p.percentile(1), None);
        assert_eq!(p.percentile(5), None);
        assert_eq!(p.percentile(99), None);
        assert_eq!(p.percentile(100), None);

        // Just a singel value.
        let p = NaiivePercentiles::new(vec![42]);
        assert_eq!(p.percentile(0).unwrap(), 42);
        assert_eq!(p.percentile(1).unwrap(), 42);
        assert_eq!(p.percentile(5).unwrap(), 42);
        assert_eq!(p.percentile(99).unwrap(), 42);
        assert_eq!(p.percentile(100).unwrap(), 42);

        let range = (1..=100).map(|x| x * 10).collect_vec();
        // sanity check
        assert_eq!(range.len(), 100);
        assert_eq!(range[10], 110);
        assert_eq!(range[99], 1000);
        let p = NaiivePercentiles::new(range);
        assert_eq!(p.percentile(0).unwrap(), 10);
        assert_eq!(p.percentile(1).unwrap(), 15);
        assert_eq!(p.percentile(2).unwrap(), 25);
        assert_eq!(p.percentile(3).unwrap(), 35);
        assert_eq!(p.percentile(4).unwrap(), 45);
        assert_eq!(p.percentile(5).unwrap(), 55);
        assert_eq!(p.percentile(50).unwrap(), 505);
        assert_eq!(p.percentile(99).unwrap(), 995);
        assert_eq!(p.percentile(100).unwrap(), 1000);
    }
}
