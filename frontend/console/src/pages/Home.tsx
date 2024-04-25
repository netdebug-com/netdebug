import { useEffect, useState } from "react";
import {
  fetchAndCheckResultWithAuth,
  loadDataWithAuth,
} from "../console_utils";
import {
  DataLoadingState,
  FirstHopPacketLossReportEntry,
  PublicOrganizationInfo,
  dataGridDefaultSxProp,
  numberSorter,
} from "../common";
import { useLoaderData } from "react-router";
import { Box, Link } from "@mui/material";
import {
  DataGrid,
  GridColDef,
  GridToolbar,
  GridValueFormatterParams,
  GridValueGetterParams,
} from "@mui/x-data-grid";

export const worstDevicesPacketLossLoader = async () => {
  const url = "api/get_worst_devices_by_packet_loss";
  const res = await fetchAndCheckResultWithAuth(url);
  return await res.json();
};

// FYI: https://mui.com/x/api/data-grid/grid-col-def/ for documentation of this madness
const columns: GridColDef[] = [
  {
    field: "name",
    headerName: "Name",
    renderCell: (
      params: GridValueGetterParams<FirstHopPacketLossReportEntry>,
    ) => {
      // name if it's defined, else uuid (which is required)
      const name = params.row.device_name
        ? params.row.device_name
        : params.row.device_uuid;
      return (
        <Link href={"/devices/device/" + params.row.device_uuid}>{name}</Link>
      );
    },
    // since we have a `renderCell` and `valueGetter`, the `renderCell` takes precedence
    // for rendering the cell. BUT, the valueGetter is used for filtering, sorting, etc.
    // so we want one.
    valueGetter: (
      params: GridValueGetterParams<FirstHopPacketLossReportEntry>,
    ) =>
      params.row.device_name ? params.row.device_name : params.row.device_uuid,
    flex: 25,
  },
  {
    field: "percent_loss",
    headerName: "%Packet Loss to First Router",
    valueFormatter: (params: GridValueFormatterParams<number>) =>
      params.value.toFixed(2) + "%",
    valueGetter: (
      params: GridValueGetterParams<FirstHopPacketLossReportEntry>,
    ) => params.row.percent_loss,
    sortComparator: numberSorter,
    flex: 10,
  },
  {
    field: "probes_recv",
    headerName: "Probes Received",
    flex: 10,
    sortComparator: numberSorter,
  },
  {
    field: "probes_sent",
    headerName: "Probes Sent",
    flex: 10,
    sortComparator: numberSorter,
  },
  {
    field: "description",
    headerName: "Description",
    flex: 25,
    align: "right",
    headerAlign: "right",
    valueGetter: (
      params: GridValueGetterParams<FirstHopPacketLossReportEntry>,
    ) => params.row.device_description,
  },
];

export function Home() {
  const [organization, setOrganization] = useState<string | null>(null);
  const worstDevicesPacketLoss =
    useLoaderData() as Array<FirstHopPacketLossReportEntry>;
  useEffect(() => {
    loadDataWithAuth(
      "api/organization_info",
      (resp: DataLoadingState<PublicOrganizationInfo>) => {
        if (resp.isPending) {
          setOrganization("Pending...");
        } else if (resp.error) {
          setOrganization("Error: " + resp.error);
        } else {
          setOrganization(resp.data.name);
        }
      },
    );
  }, []);

  const title = "Worst Devices By First-Hop Packet Loss";

  return (
    <div>
      Your organization is: {organization}
      <h2>{title}</h2>
      <Box width="50%">
        <DataGrid
          aria-label={title}
          density="compact"
          columns={columns}
          rows={worstDevicesPacketLoss}
          getRowId={(device) => device.device_uuid}
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
                probes_sent: false,
                probes_recv: false,
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
  );
}

export default Home;
