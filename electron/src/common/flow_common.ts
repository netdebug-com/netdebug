import { GridColDef } from "@mui/x-data-grid";
import { neverReached, prettyPrintSiUnits, sortCmpWithNull } from "../utils";
import {
  AggregateStatEntry,
  AggregateStatKind,
  TrafficStatsSummary,
} from "../netdebug_types";

const FLEX_VALUE_FOR_NUMERIC_COLS = 15;
export function getDefaultRateGridColDef(unitSuffix: string): {
  valueFormatter: GridColDef["valueFormatter"];
  align: GridColDef["align"];
  flex: number;
  headerAlign: GridColDef["align"];
  sortComparator: GridColDef["sortComparator"];
} {
  return {
    valueFormatter: (params) => prettyPrintSiUnits(params.value, unitSuffix),
    align: "right",
    flex: FLEX_VALUE_FOR_NUMERIC_COLS,
    headerAlign: "right",
    sortComparator: sortCmpWithNull,
  };
}

export function getDefaultRttGridColDef(): {
  valueFormatter: GridColDef["valueFormatter"];
  align: GridColDef["align"];
  flex: number;
  headerAlign: GridColDef["align"];
  sortComparator: GridColDef["sortComparator"];
} {
  return {
    valueFormatter: (params) => {
      if (params.value === null || params.value === undefined) {
        return "-";
      } else {
        return params.value.toFixed(0) + " ms";
      }
    },
    align: "right",
    flex: FLEX_VALUE_FOR_NUMERIC_COLS,
    headerAlign: "right",
    sortComparator: sortCmpWithNull,
  };
}

export function getDefaultPercentageGridColDef(): {
  valueFormatter: GridColDef["valueFormatter"];
  align: GridColDef["align"];
  flex: number;
  headerAlign: GridColDef["align"];
  sortComparator: GridColDef["sortComparator"];
} {
  return {
    valueFormatter: (params) => {
      const percent = params.value;
      return percent === null
        ? "None"
        : params.value.toFixed(1).toString() + "%";
    },
    align: "right",
    flex: FLEX_VALUE_FOR_NUMERIC_COLS,
    headerAlign: "right",
    sortComparator: sortCmpWithNull,
  };
}

export function calculateLossPercentage(
  stats: TrafficStatsSummary | null,
): number {
  if (stats === null || stats.bytes === 0 || stats.lost_bytes === null) {
    return null;
  }
  const percentage = (100 * stats.lost_bytes) / stats.bytes;
  return percentage;
}

export function aggregateStatEntryDefaultSortFn(entries: AggregateStatEntry[]) {
  return entries.sort((a, b) =>
    sortCmpWithNull(
      b.summary.rx.last_min_byte_rate,
      a.summary.rx.last_min_byte_rate,
    ),
  );
}

export function getNameFromAggKind(kind: AggregateStatKind): string {
  switch (kind.tag) {
    case "DnsDstDomain":
      return kind.name;
    case "Application":
      return kind.name;
    case "HostIp":
      return kind.name;
    case "ConnectionTracker":
      return "global";
    default:
      // exhaustive switch trick.
      neverReached(kind);
  }
}
