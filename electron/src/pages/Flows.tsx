import React, { useState } from "react";
import { ConnectionMeasurements } from "../netdebug_types";
import {
  dataGridDefaultSxProp,
  prettyPrintSiUnits,
  sortCmpWithNull,
} from "../utils";
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

// build a connection key for displaying in the table
// This key might not be unique. E.g., two different local IPs could
// have the same local port and remote pair.
// And/or a remote hostname might have to IPs.
// While this is very unlikely, react gets very angry of `key` attributes
// aren't unique.
function getConnKeyForDisplay(conn: ConnectionMeasurements) {
  const remote =
    conn.remote_hostname !== null
      ? conn.remote_hostname
      : `[${conn.key.remote_ip}]`;
  return `${conn.key.ip_proto} ${conn.key.local_l4_port} --> ${remote}:${conn.key.remote_l4_port}`;
}

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

const defaultRateGridColDef: {
  valueFormatter: GridColDef["valueFormatter"];
  align: GridColDef["align"];
  flex: number;
  headerAlign: GridColDef["align"];
  sortComparator: GridColDef["sortComparator"];
} = {
  valueFormatter: (params: GridValueFormatterParams<number>) =>
    prettyPrintSiUnits(params.value, "B/s"),
  align: "right",
  flex: 10,
  headerAlign: "right",
  sortComparator: sortCmpWithNull,
};

const columns: GridColDef[] = [
  {
    // Note, this field doesn't actually exist in ConnectionMeasurement. We use `valueGetter`
    // to derive the actual value of this field, but DataGrid still requires a unique field name
    // (e.g., for sort state, etc.)
    field: "Flow Key",
    hideable: false,
    flex: 50,
    valueGetter: (params: GridValueGetterParams<ConnectionMeasurements>) =>
      getConnKeyForDisplay(params.row),
  },
  {
    // Note, this field doesn't actually exist in ConnectionMeasurement. We use `valueGetter`
    // to derive the actual value of this field, but DataGrid still requires a unique field name
    // (e.g., for sort state, etc.)
    field: "send_bw",
    headerName: "Send B/W",
    valueGetter: (params: GridValueGetterParams<ConnectionMeasurements>) =>
      params.row.tx_stats?.last_min_byte_rate,
    ...defaultRateGridColDef,
  },
  {
    // Note, this field doesn't actually exist in ConnectionMeasurements
    field: "recv_bw",
    headerName: "Recv B/W",
    valueGetter: (params: GridValueGetterParams<ConnectionMeasurements>) =>
      params.row.rx_stats?.last_min_byte_rate,
    ...defaultRateGridColDef,
  },
  {
    field: "associated_apps",
    headerName: "Associated Apps",
    flex: 30,
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
          sx={{
            width: "100%",
            ...dataGridDefaultSxProp,
          }}
          initialState={{
            sorting: {
              sortModel: [{ field: "recv_bw", sort: "desc" }],
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
