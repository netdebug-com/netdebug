import React, { useState } from "react";
import { ConnectionMeasurements } from "../netdebug_types";
import { connIdString, dataGridDefaultSxProp, sortCmpWithNull } from "../utils";
import { SwitchHelper } from "../components/SwitchHelper";
import { useWebSocketGuiToServer } from "../useWebSocketGuiToServer";
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

const Flows: React.FC = () => {
  const [flowEntries, setFlowEntries] = useState(
    new Array<ConnectionMeasurements>(),
  );
  const [autoRefresh, setAutoRefresh] = useState(true);

  useWebSocketGuiToServer({
    autoRefresh: autoRefresh,
    reqMsgType: { tag: "DumpFlows" },
    respMsgType: "DumpFlowsReply",
    min_time_between_requests_ms: 1000,
    max_time_between_requests_ms: 2000,
    responseCb: (flows: ConnectionMeasurements[]) => {
      // DataGrid can also be "unsorted" when not sort is applied to any columns. That looks ugly,
      // so presort the rows into a reasonable default order
      flows.sort((a, b) =>
        sortCmpWithNull(
          b.rx_stats?.last_min_byte_rate,
          a.rx_stats?.last_min_byte_rate,
        ),
      );
      setFlowEntries(flows);
    },
  });

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
