import { formatValue, prettyPrintSiUnits, reshapeCounter } from "../utils";

test("prettyPrintSiUnits", () => {
  expect(prettyPrintSiUnits(null, "foo/s")).toBe("None");
  let rate = 10e9;
  expect(prettyPrintSiUnits(rate, "foo/s")).toBe("10 Gfoo/s");
  rate = 42e6;
  expect(prettyPrintSiUnits(rate, "foo/s")).toBe("42 Mfoo/s");
  rate = 23e3;
  expect(prettyPrintSiUnits(rate, "foo/s")).toBe("23 Kfoo/s");
  rate = 19;
  expect(prettyPrintSiUnits(rate, "foo/s")).toBe("19 foo/s");

  // test boundrary conditions
  rate = 1e3;
  expect(prettyPrintSiUnits(rate, "foo/s")).toBe("1 Kfoo/s");
  rate = 1e6;
  expect(prettyPrintSiUnits(rate, "foo/s")).toBe("1 Mfoo/s");
  rate = 1e9;
  expect(prettyPrintSiUnits(rate, "foo/s")).toBe("1 Gfoo/s");

  // test rounding
  rate = 1234;
  // default is 1 fraction digit
  expect(prettyPrintSiUnits(rate, "foo/s")).toBe("1.2 Kfoo/s");
  expect(prettyPrintSiUnits(rate, "foo/s", 2)).toBe("1.23 Kfoo/s");

  let x = 1e-3;
  expect(prettyPrintSiUnits(x, "sec")).toBe("1 msec");
  x = 0.1234;
  expect(prettyPrintSiUnits(x, "sec")).toBe("123.4 msec");
  x = 2e-6;
  expect(prettyPrintSiUnits(x, "sec")).toBe("2 μsec");
  x = 3e-9;
  expect(prettyPrintSiUnits(x, "sec")).toBe("3 nsec");
});

test("reshapeCounter", () => {
  const input = new Map<string, number>([
    ["foo.bar.baz.60", 61],
    ["foo.bar.baz.600", 601],
    ["foo.bar.baz.3600", 3601],
    ["foo.bar.baz", 42],

    ["asdf.SUM.60", 661],
    ["asdf.SUM.600", 6601],
    ["a_counter_without_suffix", 2323],
  ]);

  const output = reshapeCounter(input);
  expect(output.get("foo.bar.baz").get("all")).toBe(42);
  expect(output.get("foo.bar.baz").get(".60")).toBe(61);
  expect(output.get("foo.bar.baz").get(".600")).toBe(601);
  expect(output.get("foo.bar.baz").get(".3600")).toBe(3601);

  expect(output.get("asdf.SUM").get("all")).toBe(undefined);
  expect(output.get("asdf.SUM").get(".60")).toBe(661);
  expect(output.get("asdf.SUM").get(".600")).toBe(6601);
  expect(output.get("asdf.SUM").get(".3600")).toBe(undefined);

  expect(output.get("a_counter_without_suffix").get("all")).toBe(2323);
});

test("formatValue", () => {
  expect(formatValue(123456789, false)).toBe("123456789");
  expect(formatValue(123456789, true)).toMatch(/123[./,]456[/.,]789/);
  expect(formatValue(undefined, true)).toBe("");
  expect(formatValue(undefined, false)).toBe("");
});
