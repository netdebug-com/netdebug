import { rateEstimatorPrettyRate } from "../utils";
import { RateEstimator } from "../netdebug_types";

test("rateEstimatorPrettyRate", () => {
  const rate = { alpha: 0, estimate_rate_per_ns: null } as RateEstimator;

  expect(rateEstimatorPrettyRate(rate, "foo/s")).toBe("None");
  rate.estimate_rate_per_ns = 10;
  expect(rateEstimatorPrettyRate(rate, "foo/s")).toBe("10 Gfoo/s");
  rate.estimate_rate_per_ns = 42 * 1e-3;
  expect(rateEstimatorPrettyRate(rate, "foo/s")).toBe("42 Mfoo/s");
  rate.estimate_rate_per_ns = 23 * 1e-6;
  expect(rateEstimatorPrettyRate(rate, "foo/s")).toBe("23 Kfoo/s");
  rate.estimate_rate_per_ns = 19 * 1e-9;
  expect(rateEstimatorPrettyRate(rate, "foo/s")).toBe("19 foo/s");
});
