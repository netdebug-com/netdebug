import React, { useState } from "react";
import { ConnectionMeasurements } from "@netdebug/common";
import {
  connIdString,
  dataGridDefaultSxProp,
  desktop_api_url,
  sortCmpWithNull,
} from "@netdebug/common";
import { SwitchHelper } from "@netdebug/common";
import { Box } from "@mui/material";
import {
  DataGrid,
  GridColDef,
  GridToolbar,
  GridValueFormatterParams,
  GridValueGetterParams,
} from "@mui/x-data-grid";
import { FlowSummary } from "@netdebug/common";
import {
  calculateLossPercentage,
  getDefaultPercentageGridColDef,
  getDefaultGridColDefWithUnits,
  getDefaultRttGridColDef,
} from "@netdebug/common";
import { useLoaderData, useRevalidator } from "react-router";
import { usePeriodicRefresh } from "@netdebug/common";
import { fetchAndCheckResult } from "@netdebug/common";

function formatAssociatedApps(
  params: GridValueFormatterParams<ConnectionMeasurements["associated_apps"]>,
) {
  let app: string;
  if (params.value === null) {
    app = "(unknown)";
  } else {
    app = "";
    Object.entries(params.value).forEach(([x, y]) => {
      app += y === null ? `(${x})` : y;
    });
  }
  return app;
}

const columns: GridColDef[] = [
  {
    // Note, this field doesn't actually exist in ConnectionMeasurement. We use `valueGetter`
    // to derive the actual value of this field, but DataGrid still requires a unique field name
    // (e.g., for sort state, etc.)
    field: "Flow Key",
    hideable: false,
    flex: 50,
    renderCell: (params: GridValueGetterParams<ConnectionMeasurements>) => (
      <FlowSummary flow={params.row} />
    ),
  },

  {
    // Note, this field doesn't actually exist in ConnectionMeasurement. We use `valueGetter`
    // to derive the actual value of this field, but DataGrid still requires a unique field name
    // (e.g., for sort state, etc.)
    field: "send_bw",
    headerName: "Send B/W",
    valueGetter: (params: GridValueGetterParams<ConnectionMeasurements>) =>
      params.row.tx_stats?.last_min_byte_rate,
    ...getDefaultGridColDefWithUnits("B/s"),
  },
  {
    // Note, this field doesn't actually exist in ConnectionMeasurements
    field: "recv_bw",
    headerName: "Recv B/W",
    valueGetter: (params: GridValueGetterParams<ConnectionMeasurements>) =>
      params.row.rx_stats?.last_min_byte_rate,
    ...getDefaultGridColDefWithUnits("B/s"),
  },
  {
    field: "send_burst_bw",
    headerName: "Send Burst B/W",
    valueGetter: (params: GridValueGetterParams<ConnectionMeasurements>) =>
      params.row.tx_stats?.burst_byte_rate,
    ...getDefaultGridColDefWithUnits("B/s"),
  },
  {
    field: "recv_burst_bw",
    headerName: "Recv Burst B/W",
    valueGetter: (params: GridValueGetterParams<ConnectionMeasurements>) =>
      params.row.rx_stats?.burst_byte_rate,
    ...getDefaultGridColDefWithUnits("B/s"),
  },
  {
    // Note, this field doesn't actually exist in ConnectionMeasurement. We use `valueGetter`
    field: "send_bytes",
    headerName: "Send Bytes",
    valueGetter: (params) => params.row.tx_stats?.bytes,
    ...getDefaultGridColDefWithUnits("B"),
  },
  {
    // Note, this field doesn't actually exist in ConnectionMeasurement. We use `valueGetter`
    field: "recv_bytes",
    headerName: "Recv Bytes",
    valueGetter: (params) => params.row.rx_stats?.bytes,
    ...getDefaultGridColDefWithUnits("B"),
  },
  {
    // Note, this field doesn't actually exist in ConnectionMeasurement. We use `valueGetter`
    field: "send_lost_bytes",
    headerName: "Send Lost Bytes",
    valueGetter: (params) => params.row.tx_stats?.lost_bytes,
    ...getDefaultGridColDefWithUnits("B"),
  },
  {
    // Note, this field doesn't actually exist in ConnectionMeasurement. We use `valueGetter`
    field: "recv_lost_bytes",
    headerName: "Recv Lost Bytes",
    valueGetter: (params) => params.row.rx_stats?.lost_bytes,
    ...getDefaultGridColDefWithUnits("B"),
  },
  {
    // Note, this field doesn't actually exist in ConnectionMeasurement. We use `valueGetter`
    field: "send_loss",
    headerName: "Send Loss",
    valueGetter: (params) => calculateLossPercentage(params.row.tx_stats),
    ...getDefaultPercentageGridColDef(),
  },
  {
    // Note, this field doesn't actually exist in ConnectionMeasurement. We use `valueGetter`
    field: "recv_loss",
    headerName: "Recv Loss",
    valueGetter: (params) => calculateLossPercentage(params.row.rx_stats),
    ...getDefaultPercentageGridColDef(),
  },
  // TODO: instead of have three different columsn for min/avg/max RTT, I'm wondering if
  // we should instead use a single column and render it as `10ms / 14ms / 50ms` ??
  // Three columns take up a LOT of space...
  {
    field: "min_rtt",
    headerName: "min RTT",
    valueGetter: (params) => params.row.tx_stats?.rtt_stats_ms?.min,
    ...getDefaultRttGridColDef(),
  },
  {
    field: "mean_rtt",
    headerName: "avg RTT",
    valueGetter: (params) => params.row.tx_stats?.rtt_stats_ms?.mean,
    ...getDefaultRttGridColDef(),
  },
  {
    field: "max_rtt",
    headerName: "max RTT",
    valueGetter: (params) => params.row.tx_stats?.rtt_stats_ms?.max,
    ...getDefaultRttGridColDef(),
  },
  {
    field: "associated_apps",
    headerName: "Associated Apps",
    flex: 25,
    valueFormatter: formatAssociatedApps,
  },
];

export const flowsLoader = async () => {
  const res = await fetchAndCheckResult(desktop_api_url("get_flows"));
  // FIXME: error handling.
  return res.json().then((flows) =>
    // DataGrid has an unsorted state as well, which will return the rows in the original
    // order. So even though we set a default sort column, we still pre-sort here
    // to make sure the unsorted order looks decent too.
    flows.sort((a: ConnectionMeasurements, b: ConnectionMeasurements) =>
      sortCmpWithNull(
        b.rx_stats?.last_min_byte_rate,
        a.rx_stats?.last_min_byte_rate,
      ),
    ),
  );
};

const RELOAD_INTERVAL_MS = 1000;
const MAX_RELOAD_TIME = 2000;

const Flows: React.FC = () => {
  const [autoRefresh, setAutoRefresh] = useState(true);
  const flowEntries = useLoaderData() as ConnectionMeasurements[];
  // lets us re-fetch the data.
  const revalidator = useRevalidator();
  usePeriodicRefresh(
    autoRefresh,
    revalidator,
    RELOAD_INTERVAL_MS,
    "Flows",
    MAX_RELOAD_TIME,
  );

  return (
    <>
      <SwitchHelper
        text={"Auto Refresh"}
        state={autoRefresh}
        updateFn={setAutoRefresh}
      />
      <Box width="100%">
        <DataGrid
          aria-label="Table of Connections"
          density="compact"
          columns={columns}
          rows={flowEntries}
          getRowId={(row) => connIdString(row.key)}
          sx={{
            width: "100%",
            ...dataGridDefaultSxProp,
          }}
          initialState={{
            sorting: {
              sortModel: [{ field: "recv_bw", sort: "desc" }],
            },
            columns: {
              // Hide these columns by default.
              columnVisibilityModel: {
                send_burst_bw: false,
                recv_burst_bw: false,
                send_bytes: false,
                recv_bytes: false,
                send_lost_bytes: false,
                recv_lost_bytes: false,
              },
            },
          }}
          slots={{
            toolbar: GridToolbar,
          }}
          slotProps={{
            toolbar: { printOptions: { disableToolbarButton: true } },
          }}
        />
      </Box>
    </>
  );
};

export default Flows;
