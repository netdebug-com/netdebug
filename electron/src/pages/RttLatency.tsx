import React, { useState } from "react";
import {
  dataGridDefaultSxProp,
  desktop_api_url,
  sortCmpWithNull,
} from "../utils";
import { fetchAndCheckResult } from "../common/data_loading";
import { SwitchHelper } from "../components/SwitchHelper";
import { Alert, Box } from "@mui/material";
import { DataGrid, GridColDef, GridToolbar } from "@mui/x-data-grid";
import {
  getDefaultRateGridColDef as getDefaultGridColDefWithUnits,
  getDefaultRttGridColDef,
  getNameFromAggKind,
} from "../common/flow_common";
import { useLoaderData, useRevalidator } from "react-router";
import { usePeriodicRefresh } from "../usePeriodicRefresh";
import { ErrorMessage } from "../components/ErrorMessage";
import { AggregateStatEntry } from "..//netdebug_types";

export const rttLatencyLoader = async () => {
  const res = await fetchAndCheckResult(desktop_api_url("get_host_flows"));
  return res
    .json()
    .then((entries) =>
      entries
        .filter((e: AggregateStatEntry) => e.summary.tx.rtt_stats_ms !== null)
        .sort((a: AggregateStatEntry, b: AggregateStatEntry) =>
          sortCmpWithNull(
            b.summary.tx.rtt_stats_ms.max,
            a.summary.tx.rtt_stats_ms.max,
          ),
        ),
    );
};

const RELOAD_INTERVAL_MS = 1000;
const MAX_RELOAD_TIME_MS = 2000;

const columns: GridColDef[] = [
  {
    field: "id",
    headerName: "Remote Host",
    hideable: false,
    flex: 60,
    valueGetter: (params) => {
      let value = getNameFromAggKind(params.row.kind);
      if (params.row.comment !== null) {
        value = `${params.row.comment} (${value})`;
      }
      return value;
    },
  },
  {
    // Note, this field doesn't actually exist in ConnectionMeasurement. We use `valueGetter`
    field: "send_bytes",
    headerName: "Send Bytes",
    valueGetter: (params) => params.row.summary.tx.bytes,
    ...getDefaultGridColDefWithUnits("B"),
  },
  {
    // Note, this field doesn't actually exist in ConnectionMeasurement. We use `valueGetter`
    field: "recv_bytes",
    headerName: "Recv Bytes",
    valueGetter: (params) => params.row.summary.rx.bytes,
    ...getDefaultGridColDefWithUnits("B"),
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

const RttLatency: React.FC = () => {
  const statEntries = useLoaderData() as AggregateStatEntry[];
  const [autoRefresh, setAutoRefresh] = useState(true);

  const revalidator = useRevalidator();
  usePeriodicRefresh(
    autoRefresh,
    revalidator,
    RELOAD_INTERVAL_MS,
    "RttLatency",
    MAX_RELOAD_TIME_MS,
  );

  const anyInvalidKind = statEntries.some(
    (entry) => entry.kind.tag != "HostIp",
  );

  const dataGrid = (
    <Box width="100%">
      <DataGrid
        aria-label={"Table of remote hosts with their RTT/Ping Latency"}
        density="compact"
        columns={columns}
        rows={statEntries}
        getRowId={(row: AggregateStatEntry) => getNameFromAggKind(row.kind)}
        sx={{
          width: "100%",
          ...dataGridDefaultSxProp,
        }}
        initialState={{
          sorting: {
            sortModel: [{ field: "max_rtt", sort: "desc" }],
          },
          columns: {
            // Hide these columns by default.
            columnVisibilityModel: {},
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
  );

  const shouldDisplayTcpTimestampNote =
    statEntries.length == 0 &&
    navigator.platform.toLowerCase().includes("win32");
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
          {shouldDisplayTcpTimestampNote && (
            <Alert severity="info">
              Round-Trip Time Latency measurements require TCP timestamps which
              are disabled by default on Windows. To enable it, open PowerShell
              as Administrator and run{" "}
              <p>
                <code>
                  PS C:\Windows\system32&gt; Set-NetTCPSetting -timestamps
                  Enabled
                </code>
              </p>
              This setting is persisted across reboots.
            </Alert>
          )}
          {!shouldDisplayTcpTimestampNote && dataGrid}
        </div>
      )}
    </>
  );
};

export default RttLatency;
