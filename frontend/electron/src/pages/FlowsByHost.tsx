import React, { useState } from "react";
import {
  dataGridDefaultSxProp,
  desktop_api_url,
  sortCmpWithNull,
} from "../common/utils";
import { fetchAndCheckResult } from "../common/data_loading";
import { SwitchHelper } from "../common/components/SwitchHelper";
import { Alert, Box } from "@mui/material";
import { DataGrid, GridToolbar } from "@mui/x-data-grid";
import { getColumns, getNameFromAggKind } from "../common/flow_common";
import { useLoaderData, useRevalidator } from "react-router";
import { usePeriodicRefresh } from "../common/hooks/usePeriodicRefresh";
import { ErrorMessage } from "../common/components/ErrorMessage";
import { AggregateStatEntry } from "../common/netdebug_types";

export const flowsByHostLatencyLoader = async () => {
  const res = await fetchAndCheckResult(desktop_api_url("get_host_flows"));
  return res
    .json()
    .then((entries) =>
      entries.sort((a: AggregateStatEntry, b: AggregateStatEntry) =>
        sortCmpWithNull(
          b.summary.tx.rtt_stats_ms?.max,
          a.summary.tx.rtt_stats_ms?.max,
        ),
      ),
    );
};

const RELOAD_INTERVAL_MS = 1000;
const MAX_RELOAD_TIME_MS = 2000;

const columns = getColumns([
  "id",
  "send_bw",
  "recv_bw",
  "send_burst_bw",
  "recv_burst_bw",
  "send_bytes",
  "recv_bytes",
  "send_lost_bytes",
  "recv_lost_bytes",
  "send_loss",
  "recv_loss",
  "min_rtt",
  "mean_rtt",
  "max_rtt",
]);

columns[0].headerName = "Remote Host";
columns[0].valueGetter = (params) => {
  let value = getNameFromAggKind(params.row.kind);
  if (params.row.comment !== null) {
    value = `${params.row.comment} (${value})`;
  }
  return value;
};

const FlowsByHostLatency: React.FC = () => {
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
            columnVisibilityModel: {
              send_lost_bytes: false,
              recv_lost_bytes: false,
              send_burst_bw: false,
              recv_burst_bw: false,
              send_bytes: false,
              recv_bytes: false,
              send_loss: false,
              recv_loss: false,
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
  );

  const haveEntriesWithRtt = statEntries.some(
    (e: AggregateStatEntry) => e.summary.tx.rtt_stats_ms !== null,
  );
  const shouldDisplayTcpTimestampNote =
    !haveEntriesWithRtt && navigator.platform.toLowerCase().includes("win32");
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

export default FlowsByHostLatency;
