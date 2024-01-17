import React, { useRef, useState } from "react";
import { ConnectionMeasurements } from "../netdebug_types";
import {
  connIdString,
  dataGridDefaultSxProp,
  desktop_api_url,
  sortCmpWithNull,
} from "../utils";
import { SwitchHelper } from "../components/SwitchHelper";
import { Box } from "@mui/material";
import {
  DataGrid,
  GridColDef,
  GridToolbar,
  GridValueFormatterParams,
  GridValueGetterParams,
} from "@mui/x-data-grid";
import { FlowSummary } from "../components/FlowSummary";
import {
  calculateLossPercentage,
  getDefaultPercentageGridColDef,
  getDefaultRateGridColDef,
} from "../common/flow_common";
import { useLoaderData, useRevalidator } from "react-router";
// TODO: In theory RevalidationState should have been re-exported by
// by react-router. But apparently not.... Gotta love UI
import { RevalidationState } from "@remix-run/router";
import { useInterval } from "react-use";

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
    ...getDefaultRateGridColDef("B/s"),
  },
  {
    // Note, this field doesn't actually exist in ConnectionMeasurements
    field: "recv_bw",
    headerName: "Recv B/W",
    valueGetter: (params: GridValueGetterParams<ConnectionMeasurements>) =>
      params.row.rx_stats?.last_min_byte_rate,
    ...getDefaultRateGridColDef("B/s"),
  },
  {
    field: "send_burst_bw",
    headerName: "Send Burst B/W",
    valueGetter: (params: GridValueGetterParams<ConnectionMeasurements>) =>
      params.row.tx_stats?.burst_byte_rate,
    ...getDefaultRateGridColDef("B/s"),
  },
  {
    field: "recv_burst_bw",
    headerName: "Recv Burst B/W",
    valueGetter: (params: GridValueGetterParams<ConnectionMeasurements>) =>
      params.row.rx_stats?.burst_byte_rate,
    ...getDefaultRateGridColDef("B/s"),
  },
  {
    // Note, this field doesn't actually exist in ConnectionMeasurement. We use `valueGetter`
    field: "send_bytes",
    headerName: "Send Bytes",
    valueGetter: (params) => params.row.tx_stats?.bytes,
    ...getDefaultRateGridColDef("B"),
  },
  {
    // Note, this field doesn't actually exist in ConnectionMeasurement. We use `valueGetter`
    field: "recv_bytes",
    headerName: "Recv Bytes",
    valueGetter: (params) => params.row.rx_stats?.bytes,
    ...getDefaultRateGridColDef("B"),
  },
  {
    // Note, this field doesn't actually exist in ConnectionMeasurement. We use `valueGetter`
    field: "send_lost_bytes",
    headerName: "Send Lost Bytes",
    valueGetter: (params) => params.row.tx_stats?.lost_bytes,
    ...getDefaultRateGridColDef("B"),
  },
  {
    // Note, this field doesn't actually exist in ConnectionMeasurement. We use `valueGetter`
    field: "recv_lost_bytes",
    headerName: "Recv Lost Bytes",
    valueGetter: (params) => params.row.rx_stats?.lost_bytes,
    ...getDefaultRateGridColDef("B"),
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
  {
    field: "associated_apps",
    headerName: "Associated Apps",
    flex: 25,
    valueFormatter: formatAssociatedApps,
  },
];

export const flowsLoader = async () => {
  const res = await fetch(desktop_api_url("get_flows"));
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

// Sigh. useRevalidator() return type is not a named type, so we
// create and name one to keep this code neater
type RevalidatorType = {
  revalidate: () => void;
  state: RevalidationState;
};
// Helper hook to periodically refresh/reload the data via the loader.
function usePeriodicRefresh(
  // If true, periodically refresh
  autoRefresh: boolean,
  // The validator to use for refreshes
  revalidator: RevalidatorType,
  // The interval in milliseconds on when to reload
  interval_ms: number,
  // A human readable description for log messages
  description?: string,
  // If set, the maximum time we want a reload to take. If it's longer than that,
  // log an error (just to the console)
  sla_max_time_ms?: number,
) {
  const lastRequestTime = useRef(null);
  useInterval(
    () => {
      if (revalidator.state === "idle") {
        // Only send a new request if the previous one has finished
        lastRequestTime.current = performance.now();
        revalidator.revalidate();
      } else {
        // We are still loading. Check if we have an SLA and if so, log a warning if
        // it's violated.
        if (
          sla_max_time_ms &&
          performance.now() - lastRequestTime.current > sla_max_time_ms
        ) {
          console.warn(
            (description ? description + ": " : "") + "Reloading took too long",
          );
        }
      }
    },
    autoRefresh ? interval_ms : null,
  );
}

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
