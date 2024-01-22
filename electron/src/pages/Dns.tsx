import React, { useRef } from "react";
import { DnsTrackerEntry } from "../netdebug_types";
import { dataGridDefaultSxProp, desktop_api_url } from "../utils";
import { Box } from "@mui/material";
import { DataGrid, GridColDef, GridToolbar } from "@mui/x-data-grid";
import { useLoaderData, useRevalidator } from "react-router";
import { usePeriodicRefresh } from "../usePeriodicRefresh";
import { fetchAndCheckResult } from "../common/data_loading";

function format_ips(ips: string[]) {
  if (ips.length <= 1) {
    return <div>{ips.join(",")} </div>;
  } else {
    return (
      <div>
        <details>
          <summary>{ips.length} Addresses</summary>
          <ul>
            {ips.map((ip) => (
              <li
                style={{ listStyleType: "none", padding: "0", margin: "0" }}
                key={ip}
              >
                {" "}
                {ip}
              </li>
            ))}
          </ul>
        </details>
      </div>
    );
  }
}

/*********************************************************** */

export const dnsCacheLoader = async () => {
  const res = await fetchAndCheckResult(desktop_api_url("get_dns_cache"));
  return res.json().then((entries: object) => new Map(Object.entries(entries)));
};

const RELOAD_INTERVAL_MS = 500;
const MAX_RELOAD_TIME = 1000;

const Dns: React.FC = () => {
  const dnsEntries = useLoaderData() as Map<string, DnsTrackerEntry>;
  const yellow_threshold = useRef(null);
  const red_threshold = useRef(null);

  // lets us re-fetch the data.
  const revalidator = useRevalidator();
  usePeriodicRefresh(
    true /* autoRefresh */,
    revalidator,
    RELOAD_INTERVAL_MS,
    "DnsCache",
    MAX_RELOAD_TIME,
  );

  type DnsRowEntry = {
    hostname: string;
    ips: string[];
    ttl_sec?: number;
    rtt_usec?: number;
  };
  /**
   * Take as input a Map from IP -> DnsTrackerEntry and
   * re-index it to be backwards, e.g., a Map from each
   * DnsTrackerEntry to the list of IPs that were looked up
   * in that same query.  Easier for people to understand that way.
   */
  function reindex_dns(dns_map: Map<string, DnsTrackerEntry>): DnsRowEntry[] {
    const new_map = new Map<string, [DnsTrackerEntry, string[]]>();
    dns_map.forEach((dns_entry, ip) => {
      if (new_map.has(dns_entry.hostname)) {
        const entry = new_map.get(dns_entry.hostname);
        entry[1].push(ip);
      } else {
        new_map.set(dns_entry.hostname, [dns_entry, [ip]]);
      }
    });
    [yellow_threshold.current, red_threshold.current] =
      calcThresholdStats(new_map);
    const tmp = Array.from(new_map.values());
    return tmp.map(([entry, ips]) => {
      return {
        hostname: entry.hostname,
        ips: ips,
        ttl_sec: entry.ttl_sec,
        rtt_usec: entry.rtt_usec,
      };
    });
  }

  // which rtts do we color yellow and red?
  // calc avg ; yellow is avg *2 , red is avg * 4
  // NOTE: tried calculating yellow = avg + 1 stddev, red=avg + 2stddev but it
  //    made the thresholds too high!
  // becareful not to assume that all RTTs are defined and count != array.length
  const calcThresholdStats = (
    data: Map<string, [DnsTrackerEntry, string[]]>,
  ): [number, number] => {
    let sum = 0;
    let count = 0;
    // calc the avg
    data.forEach(([dns]) => {
      if (dns.rtt_usec !== null) {
        sum += dns.rtt_usec;
        count += 1;
      }
    });
    if (count === 0) {
      return [0, 0];
    }
    const avg = sum / count;
    return [avg * 2, avg * 4];
  };

  // Test the rtt vs. the yellow/red thresholds and return the matching style
  const calcStyleByRtt = (rtt_usec: number | null) => {
    if (rtt_usec === null) {
      return <div></div>;
    }
    const rtt_formatted = (rtt_usec / 1000).toLocaleString(undefined, {
      maximumFractionDigits: 1,
      minimumFractionDigits: 1,
    });
    if (rtt_usec >= red_threshold.current) {
      return (
        <div style={{ color: "red", backgroundColor: "black" }}>
          {rtt_formatted}
        </div>
      );
    } else if (rtt_usec >= yellow_threshold.current) {
      return <div style={{ color: "orange" }}>{rtt_formatted}</div>;
    } else {
      return <div>{rtt_formatted}</div>;
    }
  };

  const columns: GridColDef[] = [
    {
      field: "hostname",
      headerName: "Hostname",
      flex: 45,
    },
    {
      field: "ips",
      headerName: "IP(s)",
      flex: 25,
      sortable: false,
      renderCell: (params) => format_ips(params.value),
    },
    {
      field: "ttl_sec",
      headerName: "TTL (secs)",
      flex: 15,
      align: "right",
      headerAlign: "right",
      valueFormatter: (params) =>
        params.value === null ? "" : params.value.toLocaleString(undefined),
    },
    {
      field: "rtt_usec",
      headerName: "RTT (millis)",
      flex: 15,
      renderCell: (params) => calcStyleByRtt(params.value),
      align: "right",
      headerAlign: "right",
    },
  ];

  return (
    <div>
      <Box width="100%">
        <DataGrid
          aria-label="Table of DNS entries"
          density="compact"
          sx={{
            width: "100%",
            maxWidth: 1200,
            ...dataGridDefaultSxProp,
            // when rows are dynamically sized, density is ignored. This will restore the
            // padding again. see https://mui.com/x/react-data-grid/row-height/#dynamic-row-height
            "&.MuiDataGrid-root--densityCompact .MuiDataGrid-cell": {
              py: "8px",
            },
            "&.MuiDataGrid-root--densityStandard .MuiDataGrid-cell": {
              py: "15px",
            },
            "&.MuiDataGrid-root--densityComfortable .MuiDataGrid-cell": {
              py: "22px",
            },
          }}
          // setting this to auto will dynamically size rows.
          getRowHeight={() => "auto"}
          rows={reindex_dns(dnsEntries)}
          columns={columns}
          getRowId={(row) => row.hostname}
          initialState={{
            sorting: {
              sortModel: [{ field: "rtt_usec", sort: "desc" }],
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

export default Dns;
