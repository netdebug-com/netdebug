import React, { useState } from "react";
import { AggregateStatEntry, AggregateStatKind } from "../netdebug_types";
import { dataGridDefaultSxProp, sortCmpWithNull } from "../utils";
import { SwitchHelper } from "../components/SwitchHelper";
import { useWebSocketGuiToServer } from "../useWebSocketGuiToServer";
import { Box } from "@mui/material";
import { DataGrid, GridColDef, GridToolbar } from "@mui/x-data-grid";
import {
  calculateLossPercentage,
  getDefaultPercentageGridColDef,
  getDefaultRateGridColDef as getDefaultGridColDefWithUnits,
} from "../common/flow_common";

function getDnsNameFromAggKind(kind: AggregateStatKind) {
  return kind.tag === "DnsDstDomain" ? kind.name : "";
}

const columns: GridColDef[] = [
  {
    // Note, this field doesn't actually exist in ConnectionMeasurement. We use `valueGetter`
    field: "id",
    headerName: "DNS Destiantion Domain",
    hideable: false,
    flex: 60,
    valueGetter: (params) => getDnsNameFromAggKind(params.row.kind),
  },
  {
    // Note, this field doesn't actually exist in ConnectionMeasurement. We use `valueGetter`
    field: "send_bw",
    headerName: "Send B/W",
    valueGetter: (params) => params.row.summary.tx?.last_min_byte_rate,
    ...getDefaultGridColDefWithUnits("B/s"),
  },
  {
    // Note, this field doesn't actually exist in ConnectionMeasurement. We use `valueGetter`
    field: "recv_bw",
    headerName: "Recv B/W",
    valueGetter: (params) => params.row.summary.rx?.last_min_byte_rate,
    ...getDefaultGridColDefWithUnits("B/s"),
  },
  {
    // Note, this field doesn't actually exist in ConnectionMeasurement. We use `valueGetter`
    field: "send_bytes",
    headerName: "Send Bytes",
    valueGetter: (params) => params.row.summary.tx?.bytes,
    ...getDefaultGridColDefWithUnits("B"),
  },
  {
    // Note, this field doesn't actually exist in ConnectionMeasurement. We use `valueGetter`
    field: "recv_bytes",
    headerName: "Recv Bytes",
    valueGetter: (params) => params.row.summary.rx?.bytes,
    ...getDefaultGridColDefWithUnits("B"),
  },
  {
    // Note, this field doesn't actually exist in ConnectionMeasurement. We use `valueGetter`
    field: "send_lost_bytes",
    headerName: "Send Lost Bytes",
    valueGetter: (params) => params.row.summary.tx?.lost_bytes,
    ...getDefaultGridColDefWithUnits("B"),
  },
  {
    // Note, this field doesn't actually exist in ConnectionMeasurement. We use `valueGetter`
    field: "recv_lost_bytes",
    headerName: "Recv Lost Bytes",
    valueGetter: (params) => params.row.summary.rx?.lost_bytes,
    ...getDefaultGridColDefWithUnits("B"),
  },
  {
    // Note, this field doesn't actually exist in ConnectionMeasurement. We use `valueGetter`
    field: "send_loss",
    headerName: "Send Loss",
    valueGetter: (params) => calculateLossPercentage(params.row.summary.tx),
    ...getDefaultPercentageGridColDef(),
  },
  {
    // Note, this field doesn't actually exist in ConnectionMeasurement. We use `valueGetter`
    field: "recv_loss",
    headerName: "Recv Loss",
    valueGetter: (params) => calculateLossPercentage(params.row.summary.rx),
    ...getDefaultPercentageGridColDef(),
  },
];

const FlowsByDnsDomain: React.FC = () => {
  const [statEntries, setStatEntries] = useState(
    new Array<AggregateStatEntry>(),
  );
  const [autoRefresh, setAutoRefresh] = useState(true);

  useWebSocketGuiToServer({
    autoRefresh: autoRefresh,
    reqMsgType: { tag: "DumpDnsAggregateCounters" },
    respMsgType: "DumpDnsAggregateCountersReply",
    min_time_between_requests_ms: 1000,
    max_time_between_requests_ms: 2000,
    responseCb: (entries: AggregateStatEntry[]) => {
      entries.sort((a, b) =>
        sortCmpWithNull(
          b.summary.rx.last_min_byte_rate,
          a.summary.rx.last_min_byte_rate,
        ),
      );
      setStatEntries(entries);
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
          aria-label="Table of flows by DNS destination domain"
          density="compact"
          columns={columns}
          rows={statEntries}
          getRowId={(row: AggregateStatEntry) =>
            getDnsNameFromAggKind(row.kind)
          }
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

export default FlowsByDnsDomain;
