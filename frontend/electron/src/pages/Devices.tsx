import React from "react";
import { ExportedNeighborState } from "@netdebug/common";
import { desktop_api_url } from "@netdebug/common";
import { Box } from "@mui/material";
import { DataGrid, GridColDef, GridToolbar } from "@mui/x-data-grid";
import { useLoaderData, useRevalidator } from "react-router";
import { usePeriodicRefresh } from "../usePeriodicRefresh";

/*********************************************************** */

export const devicesLoader = async () => {
  const res = await fetch(desktop_api_url("get_devices"));
  // FIXME: error handling.
  return res.json();
};

function datetime_utc_to_relative_time(datetime_utc: string): string {
  const parsed = Date.parse(datetime_utc); // does this parse the UTC TZ correctly?
  const now = Date.now();
  const seconds = Math.floor((now - parsed) / 1000);
  return "" + seconds + "s ago";
}

const RELOAD_INTERVAL_MS = 1000;
const MAX_RELOAD_TIME = 2000;

const Devices: React.FC = () => {
  const devices = useLoaderData() as ExportedNeighborState[];

  // lets us re-fetch the data.
  const revalidator = useRevalidator();
  usePeriodicRefresh(
    true /* autoRefresh */,
    revalidator,
    RELOAD_INTERVAL_MS,
    "Devices",
    MAX_RELOAD_TIME,
  );

  const columns: GridColDef[] = [
    {
      field: "mac",
      headerName: "MAC Address",
      flex: 25,
      align: "left",
    },
    {
      field: "ip",
      headerName: "IP",
      flex: 25,
      align: "left",
      headerAlign: "left",
    },
    {
      field: "vendor_oui",
      headerName: "Vendor",
      flex: 25,
      align: "left",
      headerAlign: "left",
    },
    {
      field: "learn_time",
      headerName: "Last Seen",
      flex: 25,
      align: "right",
      headerAlign: "right",
      renderCell: (params) => datetime_utc_to_relative_time(params.value),
    },
  ];

  return (
    <div>
      {/* TODO: fix the color/style of this header */}
      <h3>As discovered by broadcast on local network</h3>
      <Box width="100%">
        <DataGrid
          aria-label="Table of Local Devices"
          density="compact"
          rows={devices}
          columns={columns}
          getRowId={(row) => row.ip}
          initialState={{
            sorting: {
              sortModel: [{ field: "learn_time", sort: "desc" }],
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
  );
};

export default Devices;
