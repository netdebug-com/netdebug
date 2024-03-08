import React, { useState } from "react";
import { AggregateStatEntry, AggregateStatKind } from "../netdebug_types";
import { SwitchHelper } from "../components/SwitchHelper";
import { Box } from "@mui/material";
import { DataGrid, GridToolbar } from "@mui/x-data-grid";
import { getColumns, getNameFromAggKind } from "../flow_common";
import { useLoaderData, useRevalidator } from "react-router";
import { usePeriodicRefresh } from "../hooks/usePeriodicRefresh";
import { ErrorMessage } from "./ErrorMessage";
import { dataGridDefaultSxProp } from "../utils";

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
]);

export interface AggregatedFlowsProps {
  headerName: string;
  expectedKind: AggregateStatKind["tag"];
  reload_interval_ms: number;
  max_reload_time_ms: number;
}

// TODO: it's convenient to just use `useLoaderData` here. But if ever want to
// use this component w/o react-router loaders, it's easy enough to change this
// and simply pass the `statsEntries` as a prop.
export const AggregatedFlows: React.FC<AggregatedFlowsProps> = (props) => {
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
