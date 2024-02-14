import {
  calcBucketIndex,
  calcHistogramParams,
} from "../components/NetworkInterfaceState";

test("calcHistorgramBucketSize", () => {
  expect(calcHistogramParams(0, 10, 100)).toStrictEqual({
    bucketSize: 1,
    bucketStart: 0,
    numBuckets: 100,
  });
  expect(calcHistogramParams(33.5, 100, 100)).toStrictEqual({
    bucketSize: 1,
    bucketStart: 33,
    numBuckets: 100,
  });
  expect(calcHistogramParams(10001, 11025, 100)).toStrictEqual({
    bucketSize: 100,
    bucketStart: 10000,
    numBuckets: 100,
  });
});

test("calcBucketIndex", () => {
  const histogramParams = {
    bucketSize: 1,
    bucketStart: 0,
    numBuckets: 100,
  };
  expect(calcBucketIndex(5, histogramParams)).toBe(5);
  expect(calcBucketIndex(42.5, histogramParams)).toBe(42);
});
