import { PublicDeviceDetails } from "../common";

import {
  dataGridDefaultSxProp,
  numberSorter,
  percentStringSorter,
  sortCmpWithNull,
} from "../common/utils";

import { Box, Link } from "@mui/material";
import {
  DataGrid,
  GridColDef,
  GridToolbar,
  GridValueFormatterParams,
  GridValueGetterParams,
} from "@mui/x-data-grid";
import { fetchAndCheckResultWithAuth } from "../console_utils";
import { useLoaderData } from "react-router";

export const devicesLoader = async () => {
  const url = "api/get_devices_details";
  const res = await fetchAndCheckResultWithAuth(url);
  return res.json().then((devices) =>
    // DataGrid has an unsorted state as well, which will return the rows in the original
    // order. So even though we set a default sort column, we still pre-sort here
    // to make sure the unsorted order looks decent too.
    devices.sort((a: PublicDeviceDetails, b: PublicDeviceDetails) => {
      const a_badness = Math.max(
        a.num_flows_with_recv_loss,
        a.num_flows_with_send_loss,
      );
      const b_badness = Math.max(
        b.num_flows_with_recv_loss,
        b.num_flows_with_send_loss,
      );
      return sortCmpWithNull(b_badness, a_badness);
    }),
  );
};

// FYI: https://mui.com/x/api/data-grid/grid-col-def/ for documentation of this madness
const columns: GridColDef[] = [
  {
    field: "name",
    headerName: "Name",
    renderCell: (params: GridValueGetterParams<PublicDeviceDetails>) => {
      // name if it's defined, else uuid (which is required)
      const name = params.row.device_info.name
        ? params.row.device_info.name
        : params.row.device_info.uuid;
      return (
        <Link href={"/devices/device/" + params.row.device_info.uuid}>
          {name}
        </Link>
      );
    },
    flex: 25,
  },
  {
    field: "num_flows_stored",
    headerName: "Flows Stored",
    flex: 10,
    sortComparator: numberSorter,
  },
  {
    field: "num_flows_with_send_loss",
    headerName: "Tx Flows w/Loss",
    flex: 10,
    sortComparator: numberSorter,
  },
  {
    field: "num_flows_with_recv_loss",
    headerName: "Rx Flows w/Loss",
    flex: 10,
    sortComparator: numberSorter,
  },
  {
    field: "percent_flows_with_loss",
    headerName: "% Flow w/Loss",
    valueGetter: (params: GridValueGetterParams<PublicDeviceDetails>) => {
      const max_loss = Math.max(
        params.row.num_flows_with_recv_loss,
        params.row.num_flows_with_send_loss,
      );
      if (params.row.num_flows_stored == 0) {
        return 0; // protect against divide by zero
      } else {
        return (
          ((100 * max_loss) / params.row.num_flows_stored).toFixed(2) + "%"
        );
      }
    },
    flex: 10,
    sortComparator: percentStringSorter,
  },
  {
    field: "oldest_flow_time",
    headerName: "Oldest Flow Time",
    valueFormatter: (params: GridValueFormatterParams<string>) =>
      new Date(params.value).toLocaleString(),
    flex: 15,
  },
  {
    field: "newest_flow_time",
    type: "Date",
    headerName: "Newest Flow Time",
    valueFormatter: (params: GridValueFormatterParams<string>) =>
      new Date(params.value).toLocaleString(),
    flex: 15,
  },
  {
    field: "uuid",
    headerName: "Uuid",
    flex: 25,
    valueGetter: (params: GridValueGetterParams<PublicDeviceDetails>) =>
      params.row.device_info.uuid,
  },
  {
    field: "organization_id",
    headerName: "Organization ID",
    flex: 15,
    align: "right",
    headerAlign: "right",
    valueGetter: (params: GridValueGetterParams<PublicDeviceDetails>) =>
      params.row.device_info.organization_id,
  },
  {
    field: "description",
    headerName: "Description",
    flex: 25,
    align: "right",
    headerAlign: "right",
    valueGetter: (params) => params.row.device_info.description,
  },
  {
    field: "created",
    headerName: "Created",
    flex: 20,
    align: "right",
    headerAlign: "right",
    valueGetter: (params) => params.row.device_info.created,
  },
];

export function Devices() {
  const devices = useLoaderData() as PublicDeviceDetails[];
  return (
    <Box width="100%">
      <DataGrid
        aria-label="Table of Connections"
        density="compact"
        columns={columns}
        rows={devices}
        getRowId={(device) => device.device_info.uuid}
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
              uuid: false,
              created: false,
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
