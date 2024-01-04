import { GridColDef } from "@mui/x-data-grid";
import { prettyPrintSiUnits, sortCmpWithNull } from "../utils";
import { TrafficStatsSummary } from "../netdebug_types";

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
