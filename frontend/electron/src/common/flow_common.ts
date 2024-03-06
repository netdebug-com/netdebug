import { GridColDef } from "@mui/x-data-grid";
import { neverReached, prettyPrintSiUnits, sortCmpWithNull } from "../utils";
import {
  AggregateStatEntry,
  AggregateStatKind,
  TrafficStatsSummary,
} from "../netdebug_types";

const FLEX_VALUE_FOR_NUMERIC_COLS = 15;
export function getDefaultGridColDefWithUnits(unitSuffix: string): {
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

export function getColumns(fieldsToInclude: string[]) {
  const defaultColumns: GridColDef[] = [
    {
      field: "id",
      headerName: "Name",
      hideable: false,
      flex: 60,
      valueGetter: (params) => getNameFromAggKind(params.row.kind),
    },
    {
      field: "send_bw",
      headerName: "Send B/W",
      valueGetter: (params) => params.row.summary.tx?.last_min_byte_rate,
      ...getDefaultGridColDefWithUnits("B/s"),
    },
    {
      field: "recv_bw",
      headerName: "Recv B/W",
      valueGetter: (params) => params.row.summary.rx?.last_min_byte_rate,
      ...getDefaultGridColDefWithUnits("B/s"),
    },
    {
      field: "send_burst_bw",
      headerName: "Send Burst B/W",
      valueGetter: (params) => params.row.summary.tx?.burst_byte_rate,
      ...getDefaultGridColDefWithUnits("B/s"),
    },
    {
      field: "recv_burst_bw",
      headerName: "Recv Burst B/W",
      valueGetter: (params) => params.row.summary.rx?.burst_byte_rate,
      ...getDefaultGridColDefWithUnits("B/s"),
    },
    {
      field: "send_bytes",
      headerName: "Send Bytes",
      valueGetter: (params) => params.row.summary.tx?.bytes,
      ...getDefaultGridColDefWithUnits("B"),
    },
    {
      field: "recv_bytes",
      headerName: "Recv Bytes",
      valueGetter: (params) => params.row.summary.rx?.bytes,
      ...getDefaultGridColDefWithUnits("B"),
    },
    {
      field: "send_lost_bytes",
      headerName: "Send Lost Bytes",
      valueGetter: (params) => params.row.summary.tx?.lost_bytes,
      ...getDefaultGridColDefWithUnits("B"),
    },
    {
      field: "recv_lost_bytes",
      headerName: "Recv Lost Bytes",
      valueGetter: (params) => params.row.summary.rx?.lost_bytes,
      ...getDefaultGridColDefWithUnits("B"),
    },
    {
      field: "send_loss",
      headerName: "Send Loss",
      valueGetter: (params) => calculateLossPercentage(params.row.summary.tx),
      ...getDefaultPercentageGridColDef(),
    },
    {
      field: "recv_loss",
      headerName: "Recv Loss",
      valueGetter: (params) => calculateLossPercentage(params.row.summary.rx),
      ...getDefaultPercentageGridColDef(),
    },
    {
      field: "min_rtt",
      headerName: "min RTT",
      valueGetter: (params) => params.row.summary.tx.rtt_stats_ms?.min,
      ...getDefaultRttGridColDef(),
    },
    {
      field: "mean_rtt",
      headerName: "avg RTT",
      valueGetter: (params) => params.row.summary.tx.rtt_stats_ms?.mean,
      ...getDefaultRttGridColDef(),
    },
    {
      field: "max_rtt",
      headerName: "max RTT",
      valueGetter: (params) => params.row.summary.tx.rtt_stats_ms?.max,
      ...getDefaultRttGridColDef(),
    },
  ];

  const allFieldNames = defaultColumns.map((colDef) => colDef.field);

  fieldsToInclude.forEach((field) => {
    // sanity check. Ideally, this would be a unit test....
    if (!allFieldNames.includes(field)) {
      throw new Error(`Field name ${field} is not a field`);
    }
  });
  return defaultColumns.filter((colDef) =>
    fieldsToInclude.includes(colDef.field),
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
