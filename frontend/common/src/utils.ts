// check how long it's been since our last message and send now or later

import { SxProps } from "@mui/material";
import { ConnectionKey, ConnectionMeasurements } from "./netdebug_types";

export function desktop_api_url(path: string): string {
  return "http://localhost:33434/api/" + path;
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

// Test the value vs. the yellow/red thresholds and return the matching style
export function calcStyleByThreshold(
  value: number,
  mid: number,
  high: number,
): SxProps {
  if (value >= high) {
    return { color: "red", backgroundColor: "black" };
  } else if (value >= mid) {
    return { color: "orange" };
  } else {
    return {};
  }
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
    // @ts-expect-error rowMap.get()'s type says it could return undefined but we set it in the line above
    rowMap.get(name)[what] = value;
  }
  return Array.from(rowMap.values()).sort((a, b) => a.id.localeCompare(b.id));
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

export function sortCmpWithNull(a: number | null, b: number | null) {
  a = a || 0;
  b = b || 0;
  return a - b;
}

export const dataGridDefaultSxProp = {
  minWidth: 650,
  "& .MuiDataGrid-columnHeaders": {
    // https://mui.com/material-ui/customization/palette/
    backgroundColor: "primary.main",
    color: "primary.contrastText",
    fontWeight: "bold",
    // Apparently DataGrid overrides fontWeidht with the following
    // css variable. So lets hack it to get the header to render in bold.
    "--unstable_DataGrid-headWeight": "bold",
  },
  "& .MuiDataGrid-sortIcon": {
    color: "primary.contrastText",
  },
  "& .MuiDataGrid-menuIconButton": {
    color: "primary.contrastText",
  },
};

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

// External style sheets are for loser...
export const headerStyleLight = {
  // Looks like MUI has a color palette and we can refer to these
  // colors :-)
  // https://mui.com/material-ui/customization/palette/
  color: "primary.dark",
  fontWeight: "bold",
};

// Re-use the header style but a width
// See https://mui.com/system/getting-started/the-sx-prop/#sizing
// For an explanation of what the width means exactly.
// But values < 1.0 are translated into percent (0.5 -> 50%)
// Otherwise the unit is `px`
export function headerStyleWithWidthLight(width: number) {
  return { ...headerStyleLight, width: width, minWidth: width };
}

// build a connection key for displaying in the table
// This key might not be unique. E.g., two different local IPs could
// have the same local port and remote pair.
// And/or a remote hostname might have to IPs.
// While this is very unlikely, react gets very angry of `key` attributes
// aren't unique.
export function getConnKeyForDisplay(conn: ConnectionMeasurements) {
  const remote =
    conn.remote_hostname !== null
      ? conn.remote_hostname
      : `[${conn.key.remote_ip}]`;
  return `${conn.key.ip_proto} ${conn.key.local_l4_port} --> ${remote}:${conn.key.remote_l4_port}`;
}

// Helper function using TS's never type. If a call to this function is ever reachable,
// TS will show a type error. Can be used for exhaustive switch statements.
// https://medium.com/technogise/type-safe-and-exhaustive-switch-statements-aka-pattern-matching-in-typescript-e3febd433a7a
export function neverReached(x: never) {
  throw new Error("This will never be reached " + x);
}

// Convert a ConnectionKey into an opaque string representation.  This
// allows to use the UI as a unique id (e.g., for react `key` fields) and it allows the UI
// to send request for a particular connection or set of connections
export function connIdString(key: ConnectionKey): string {
  // WARNING WARNING: This implemenation MUST match the implementation of
  // WARNING WARNING: ConnectionIdString::from<ConnectionKey> in rust (connection_key.rs)
  // WARNING WARNING: It is used to identify connections between UI and desktop

  // Ok, using TS's never type to make sure we exhaustively cover all cases of IpProtocol.
  let proto = 0;
  if (typeof key.ip_proto == "string") {
    switch (key.ip_proto) {
      case "ICMP":
        proto = 1;
        break;
      case "TCP":
        proto = 6;
        break;
      case "UDP":
        proto = 17;
        break;
      case "ICMP6":
        proto = 58;
        break;
      default:
        // If there's a new string variant added, the following line
        // show a type error
        neverReached(key.ip_proto);
    }
  } else if ("Other" in key.ip_proto) {
    // Because of crappy why serde encodes rust enums by default, we need to jump
    // through this hoop with the "in" check. And we can't easily change IpProtocol
    // to be adjacently tagged since we've already stored a bunch :-(
    proto = key.ip_proto.Other;
  } else {
    // If there's a new non-string variant added, the following line
    // show a type error
    neverReached(key.ip_proto);
  }

  return [
    proto,
    key.local_ip,
    key.local_l4_port,
    key.remote_ip,
    key.remote_l4_port,
  ].join("#");
}
