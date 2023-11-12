import { prettyPrintSiUnits } from "../utils";

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
});
