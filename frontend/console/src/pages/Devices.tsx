import { PublicDeviceInfo } from "../common";

import { dataGridDefaultSxProp, sortCmpWithNull } from "../common/utils";

import { Box, Link } from "@mui/material";
import { DataGrid, GridColDef, GridToolbar } from "@mui/x-data-grid";
import { fetchAndCheckResultWithAuth } from "../console_utils";
import { useLoaderData } from "react-router";

export const devicesLoader = async () => {
  const url = "api/get_devices";
  const res = await fetchAndCheckResultWithAuth(url);
  return res.json().then((devices) =>
    // DataGrid has an unsorted state as well, which will return the rows in the original
    // order. So even though we set a default sort column, we still pre-sort here
    // to make sure the unsorted order looks decent too.
    devices.sort((a: PublicDeviceInfo, b: PublicDeviceInfo) =>
      sortCmpWithNull(Date.parse(b.created), Date.parse(a.created)),
    ),
  );
};
const columns: GridColDef[] = [
  {
    field: "name",
    headerName: "Name",
    flex: 15,
  },
  {
    field: "uuid",
    headerName: "Uuid",
    flex: 25,
    renderCell: (params) => (
      <Link href={"/devices/device/" + params.value}>{params.value}</Link>
    ),
  },
  {
    field: "organization_id",
    headerName: "Organization ID",
    flex: 15,
    align: "right",
    headerAlign: "right",
  },
  {
    field: "description",
    headerName: "Description",
    flex: 25,
    align: "right",
    headerAlign: "right",
  },
  {
    field: "created",
    headerName: "Created",
    flex: 20,
    align: "right",
    headerAlign: "right",
  },
];

export function Devices() {
  const devices = useLoaderData() as PublicDeviceInfo[];
  return (
    <Box width="100%">
      <DataGrid
        aria-label="Table of Connections"
        density="compact"
        columns={columns}
        rows={devices}
        getRowId={(device) => device.uuid}
        sx={{
          width: "100%",
          ...dataGridDefaultSxProp,
        }}
        initialState={{
          sorting: {
            sortModel: [{ field: "created", sort: "desc" }],
          },
          columns: {
            // Hide these columns by default.
            columnVisibilityModel: {
              organization_id: false,
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
}

export default Devices;
