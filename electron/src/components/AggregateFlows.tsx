import React, { useState } from "react";
import { AggregateStatEntry, AggregateStatKind } from "../netdebug_types";
import { dataGridDefaultSxProp, neverReached } from "../utils";
import { SwitchHelper } from "../components/SwitchHelper";
import { Box } from "@mui/material";
import { DataGrid, GridColDef, GridToolbar } from "@mui/x-data-grid";
import {
  calculateLossPercentage,
  getDefaultPercentageGridColDef,
  getDefaultRateGridColDef as getDefaultGridColDefWithUnits,
} from "../common/flow_common";
import { useLoaderData, useRevalidator } from "react-router";
import { usePeriodicRefresh } from "../usePeriodicRefresh";
import { ErrorMessage } from "./ErrorMessage";

function getNameFromAggKind(kind: AggregateStatKind): string {
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

const columns: GridColDef[] = [
  {
    // Note, this field doesn't actually exist in ConnectionMeasurement. We use `valueGetter`
    field: "id",
    headerName: "Name",
    hideable: false,
    flex: 60,
    valueGetter: (params) => getNameFromAggKind(params.row.kind),
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
    field: "send_burst_bw",
    headerName: "Send Burst B/W",
    valueGetter: (params) => params.row.summary.tx?.burst_byte_rate,
    ...getDefaultGridColDefWithUnits("B/s"),
  },
  {
    // Note, this field doesn't actually exist in ConnectionMeasurement. We use `valueGetter`
    field: "recv_burst_bw",
    headerName: "Recv Burst B/W",
    valueGetter: (params) => params.row.summary.rx?.burst_byte_rate,
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

export interface AggregatedFlowsProps {
  headerName: string;
  expectedKind: AggregateStatKind["tag"];
  reload_interval_ms: number;
  max_reload_time_ms: number;
}

// TODO: it's convenient to just use `useLoaderData` here. But if ever want to
// use this component w/o react-router loaders, it's easy enough to change this
// and simply pass the `statsEntries` as a prop.
const AggregatedFlows: React.FC<AggregatedFlowsProps> = (props) => {
  const statEntries = useLoaderData() as AggregateStatEntry[];
  const [autoRefresh, setAutoRefresh] = useState(true);

  const revalidator = useRevalidator();
  usePeriodicRefresh(
    autoRefresh,
    revalidator,
    props.reload_interval_ms,
    "AggregatedFlows/" + props.headerName,
    props.max_reload_time_ms,
  );

  columns[0].headerName = props.headerName;
  const anyInvalidKind = statEntries.some(
    (entry) => entry.kind.tag != props.expectedKind,
  );

  return (
    <>
      {anyInvalidKind && (
        <ErrorMessage msg={"ERROR: Invalid AggregateStatKinds passed"} />
      )}
      {!anyInvalidKind && (
        <div>
          <SwitchHelper
            text={"Auto Refresh"}
            state={autoRefresh}
            updateFn={setAutoRefresh}
          />
          <Box width="100%">
            <DataGrid
              aria-label={"Table of flows by " + props.headerName}
              density="compact"
              columns={columns}
              rows={statEntries}
              getRowId={(row: AggregateStatEntry) =>
                getNameFromAggKind(row.kind)
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
                    send_burst_bw: false,
                    recv_burst_bw: false,
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
        </div>
      )}
    </>
  );
};

export default AggregatedFlows;
