import React, { useState } from "react";
import { AggregateStatEntry, AggregateStatKind } from "../netdebug_types";
import {
  dataGridDefaultSxProp,
  desktop_api_url,
  sortCmpWithNull,
} from "../utils";
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
import { fetchAndCheckResult } from "../common/data_loading";

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

export const flowsByDnsDomainLoader = async () => {
  const res = await fetchAndCheckResult(desktop_api_url("get_dns_flows"));
  return res
    .json()
    .then((entries: AggregateStatEntry[]) =>
      entries.sort((a, b) =>
        sortCmpWithNull(
          b.summary.rx.last_min_byte_rate,
          a.summary.rx.last_min_byte_rate,
        ),
      ),
    );
};

const RELOAD_INTERVAL_MS = 1000;
const MAX_RELOAD_TIME = 2000;

const FlowsByDnsDomain: React.FC = () => {
  const statEntries = useLoaderData() as AggregateStatEntry[];
  const [autoRefresh, setAutoRefresh] = useState(true);

  const revalidator = useRevalidator();
  usePeriodicRefresh(
    autoRefresh,
    revalidator,
    RELOAD_INTERVAL_MS,
    "FlowsByDnsDomain",
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
    </>
  );
};

export default FlowsByDnsDomain;
