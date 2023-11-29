// check how long it's been since our last message and send now or later

import { MutableRefObject } from "react";
import { ConnectionKey } from "./netdebug_types";

// depending on our SLAs
export function periodic_with_sla(
  label: string,
  timeout_id: MutableRefObject<NodeJS.Timeout>,
  last_send: MutableRefObject<number>,
  min: number,
  max: number,
  callback: () => void,
) {
  const send_delta = performance.now() - last_send.current;
  if (send_delta <= min) {
    timeout_id.current = setTimeout(callback, min - send_delta);
  } else {
    timeout_id.current = null;
    callback();
    if (send_delta > max) {
      console.warn(label + " reply delayed beyond SLA " + max + "ms");
    }
  }
}

/// Given a number return a scale and suffix for the appropriate SI magnitude.
/// E.g., 1234 would be [1000, "K"]. So 1234/1000 == 1.234 K
export function getSiScale(x: number): [number, string] {
  x = Math.abs(x);
  if (x >= 1e9) {
    return [1e9, "G"];
  }
  if (x >= 1e6) {
    return [1e6, "M"];
  }
  if (x >= 1e3) {
    return [1e3, "K"];
  }
  if (x >= 1) {
    return [1, ""];
  }
  if (x >= 1e-3) {
    return [1e-3, "m"];
  }
  if (x >= 1e-6) {
    return [1e-6, "μ"];
  }
  if (x >= 1e-9) {
    return [1e-9, "n"];
  }
  return [1, ""];
}

/// pretty print units using SI prefixes (K, M, G).
// x: the number to format
// unitSuffix: the suffix to add. E.g., "Bytes/s".
// example: prettyPrintSiUnits(2.5e6, "Bytes/s") ==> 2.50 MBytes/s
export function prettyPrintSiUnits(
  x: number | null,
  unitSuffix: string,
  maximumFractionDigits?: number,
): string {
  if (x === null || x === undefined) {
    return "None";
  }
  const opts = {
    maximumFractionDigits: maximumFractionDigits ? maximumFractionDigits : 1,
  };
  const [scale, suffix] = getSiScale(x);
  return (
    (x / scale).toLocaleString(undefined, opts) + " " + suffix + unitSuffix
  );
}

// Utility function that takes a Map<string, number> containing stat counter values
// and reshapes them. It extracts the basename of the counter name (i.e., without the .60, .600,
// .3600 suffixes) and returns a new map: `counter_basname -> Map<TimeWindowStrings, number>"
export type CounterRow = {
  id: string;
  t60?: number;
  t600?: number;
  t3600?: number;
  all?: number;
};
export type TimeWindowStrings = "t60" | "t600" | "t3600" | "all";
export function reshapeCounter(counter_map: Map<string, number>): CounterRow[] {
  const rowMap: Map<string, CounterRow> = new Map();

  for (const entry of counter_map) {
    let name = entry[0];
    const value = entry[1];
    let what: TimeWindowStrings = "all";
    for (const suffix of [".60", ".600", ".3600"]) {
      if (name.endsWith(suffix)) {
        what = suffix.replace(".", "t") as TimeWindowStrings;
        name = name.replace(suffix, "");
        break;
      }
    }
    if (!rowMap.has(name)) {
      rowMap.set(name, { id: name });
    }
    rowMap.get(name)[what] = value;
  }
  return Array.from(rowMap.values());
}

// Format a numeric value as a string, adding thousand seperators if desired.
export function formatValue(
  val: number | undefined | null,
  renderThousandSep: boolean,
): string {
  if (val === undefined || val === null) {
    return "";
  } else if (renderThousandSep) {
    return val.toLocaleString();
  } else {
    return val.toString();
  }
}

// build a unique connection key, using the same fields the
// rust logic uses.
export function connKeyToStr(key: ConnectionKey) {
  return (
    `${key.ip_proto}-[${key.local_ip}]:${key.local_l4_port}` +
    `-[${key.remote_ip}]:${key.remote_l4_port}`
  );
}

// External style sheets are for loser...
export const headerStyle = {
  // Looks like MUI has a color palette and we can refer to these
  // colors :-)
  // https://mui.com/material-ui/customization/palette/
  backgroundColor: "primary.main",
  color: "primary.contrastText",
  fontWeight: "bold",
  // Apparently DataGrid overrides fontWeidht with the following
  // css variable. So lets hack it to get the header to render in bold.
  "--unstable_DataGrid-headWeight": "bold",
};

// Re-use the header style but a width
// See https://mui.com/system/getting-started/the-sx-prop/#sizing
// For an explanation of what the width means exactly.
// But values < 1.0 are translated into percent (0.5 -> 50%)
// Otherwise the unit is `px`
export function headerStyleWithWidth(width: number) {
  return { ...headerStyle, width: width, minWidth: width };
}
