import Table from "@mui/material/Table";
import TableCell from "@mui/material/TableCell";
import TableContainer from "@mui/material/TableContainer";
import TableHead from "@mui/material/TableHead";
import TableRow from "@mui/material/TableRow";
import Paper from "@mui/material/Paper";
import {
  ConnectionKey,
  ConnectionMeasurements,
  ExportedSimpleStats,
  ProbeReportSummaryNode,
  TrafficStatsSummary,
} from "../netdebug_types";
import { usePeriodicRefresh } from "../hooks/usePeriodicRefresh";
import { SwitchHelper } from "./SwitchHelper";
import {
  connIdString,
  desktop_api_url,
  formatAssociatedApps,
  normalTableHeaderStyle,
  prettyPrintDuration,
  prettyPrintSiUnits,
} from "../utils";
import { FlowSummaryProps } from "./FlowSummary";
import { useLoaderData, useNavigate, useRevalidator } from "react-router-dom";
import React, { ReactElement, useState } from "react";
import { Button, Stack, TableBody } from "@mui/material";
import ReactApexChart from "react-apexcharts";
import { ApexOptions } from "apexcharts";

function request_probe_flow(connId: ConnectionKey) {
  const url = desktop_api_url("probe_flow") + "/" + connIdString(connId);
  fetch(url)
    .then((res) => {
      if (!res.ok) {
        res.text().then((textMsg) => {
          console.error(
            "Failed to request probe_flow:",
            res.status,
            res.statusText,
            ":",
            textMsg,
          );
        });
      }
    })
    .catch((err) => {
      console.error(err.message);
    });
}

function request_ping_tree(connId: ConnectionKey) {
  const url =
    desktop_api_url("pingtree_probe_flow") + "/" + connIdString(connId);
  fetch(url)
    .then((res) => {
      if (!res.ok) {
        res.text().then((textMsg) => {
          console.error(
            "Failed to request pingtree_probe_flow:",
            res.status,
            res.statusText,
            ":",
            textMsg,
          );
        });
      }
    })
    .catch((err) => {
      console.error(err.message);
    });
}

// Re-usable components to show the detailed information in a flow
// Assumes we already have the corresponding connection measurement
// The 'FlowSummary' is a one-line description of the flow - suitable for a list, but it's clickable
// so that it can popover a more detailed analysys of that flow
const RELOAD_INTERVAL_MS = 1000;
const MAX_RELOAD_TIME = 2000;

interface ProbeVariance {
  median: number;
  max: number;
  variance: number;
}

function measurementsToProbeVariance(
  connectionMeasurements: ConnectionMeasurements,
): Array<[string, ProbeVariance]> {
  const hop2ProbeVariance = new Map<string, ProbeVariance>();
  // step #1: compute the median/p50 and max for each hop in the summary
  Object.entries(connectionMeasurements.probe_report_summary.summary).forEach(
    ([ttl, probes]: [string, ProbeReportSummaryNode[]]) => {
      probes.forEach((probe: ProbeReportSummaryNode) => {
        if (probe.ip && probe.rtts.length > 0) {
          // only look at probe groups where we got a remote IP and >=1 RTT
          const key: string = "Hop " + ttl + ": " + probe.ip;
          probe.rtts.sort((a, b) => a - b);
          // .toFixed(2) --> just look at two digits after the decimal, but returns a string
          // Number(str) --> convert a string back to a number... %(*&@) you Javascript
          const median = Number(
            probe.rtts[Math.floor(probe.rtts.length / 2)].toFixed(2),
          );
          const max = Number(probe.rtts[probe.rtts.length - 1].toFixed(2));
          const variance = {
            median: median,
            max: max,
            variance: Number((max - median).toFixed(2)),
          };
          hop2ProbeVariance.set(key, variance);
        } else {
          // TODO: decide how/if to include the EndHost data which we're currently ignoring
        }
      });
    },
  );
  // TODO: decide how/if to include the pingtree data if we have it
  const probeVariances = Array.from(hop2ProbeVariance).sort(
    ([, a_probe], [, b_probe]) => b_probe.variance - a_probe.variance,
  );
  return probeVariances;
}

function probeReportToApexChartsOptions(
  hop2ProbeVariance: Array<[string, ProbeVariance]>,
): ApexOptions {
  return {
    chart: {
      type: "bar",
      height: 350,
      stacked: true,
    },
    plotOptions: {
      bar: {
        horizontal: true,
        dataLabels: {
          total: {
            enabled: false,
            offsetX: 0,
            style: {
              fontSize: "13px",
              fontWeight: 900,
            },
          },
        },
      },
    },
    stroke: {
      width: 1,
      colors: ["#fff"],
    },
    title: {
      text: "Latency and Congestion Per Hop (Congestion = Max RTT - Median RTT)",
    },
    xaxis: {
      categories: hop2ProbeVariance.map(([hop]) => hop),
      title: {
        text: "RTT (milliseconds)",
      },
    },
    fill: {
      opacity: 1,
    },
    legend: {
      position: "top",
      horizontalAlign: "left",
      offsetX: 40,
    },
  };
}

function probeReportToApexChartsSeries(
  hop2ProbeVariance: Array<[string, ProbeVariance]>,
): ApexOptions["series"] {
  const median_data = {
    name: "Network RTT",
    data: hop2ProbeVariance.map(
      ([, probe]: [string, ProbeVariance]) => probe.median,
    ),
  };
  const variance_data = {
    name: "Congestion Delay",
    data: hop2ProbeVariance.map(
      ([, probe]: [string, ProbeVariance]) => probe.variance,
    ),
  };
  // console.log("Median data", JSON.stringify(median_data, undefined, 2));
  // console.log("Variance data", JSON.stringify(variance_data, undefined, 2));
  return [median_data, variance_data];
}

function renderProbeReport(
  flow: ConnectionMeasurements,
): import("react").ReactNode {
  const hop2ProbeVariance = measurementsToProbeVariance(flow);
  if (flow.key.ip_proto == "TCP") {
    return (
      <div id="chart">
        <ReactApexChart
          options={probeReportToApexChartsOptions(hop2ProbeVariance)}
          series={probeReportToApexChartsSeries(hop2ProbeVariance)}
          type="bar"
          height={350}
        />
        <details>
          <summary>Raw JSON Struct</summary>
          <pre>{JSON.stringify(flow, undefined, 2)} </pre>
        </details>
      </div>
    );
  } else {
    return (
      <div>
        <b>Coming soon! Probing for {String(flow.key.ip_proto)} type flows </b>
        {JSON.stringify(flow, undefined, 2)}
      </div>
    );
  }
}

function getTxRxCell(
  flow: ConnectionMeasurements,
  label: string,
  key: keyof TrafficStatsSummary,
  unitSuffix: string,
  maximumFractionDigits?: number,
): ReactElement {
  return (
    <TableRow>
      <TableCell> {label}</TableCell>
      {/* Type coerce to a Number b/c in theory we could call with key=="rtt_stats_ms" 
        which is not a Number (but don't do that)
      */}
      <TableCell>
        {flow.tx_stats
          ? prettyPrintSiUnits(
              Number(flow.tx_stats[key]),
              unitSuffix,
              maximumFractionDigits,
            )
          : "-"}
      </TableCell>
      <TableCell>
        {flow.rx_stats
          ? prettyPrintSiUnits(
              Number(flow.rx_stats[key]),
              unitSuffix,
              maximumFractionDigits,
            )
          : "-"}
      </TableCell>
    </TableRow>
  );
}

function getTxRxRttCell(
  flow: ConnectionMeasurements,
  label: string,
  key: keyof ExportedSimpleStats,
  unitSuffix: string,
): ReactElement {
  return (
    <TableRow>
      <TableCell> {label}</TableCell>
      <TableCell>
        {flow.tx_stats && flow.tx_stats.rtt_stats_ms
          ? flow.tx_stats.rtt_stats_ms[key].toFixed(2)
          : "- "}
        {unitSuffix}
      </TableCell>
      <TableCell>
        {flow.rx_stats && flow.rx_stats.rtt_stats_ms
          ? flow.rx_stats.rtt_stats_ms[key].toFixed(2)
          : "- "}
        {unitSuffix}
      </TableCell>
    </TableRow>
  );
}

export const FlowDetails: React.FC<FlowSummaryProps> = (props) => {
  const navigate = useNavigate();
  const [autoRefresh, setAutoRefresh] = useState(true);
  const revalidator = useRevalidator();
  usePeriodicRefresh(
    autoRefresh,
    revalidator,
    RELOAD_INTERVAL_MS,
    "Flow Details",
    MAX_RELOAD_TIME,
  );
  function renderTxRxGraph(
    flow: ConnectionMeasurements,
  ): import("react").ReactNode {
    return (
      <Stack spacing={2} direction="row" sx={{ margin: "20px" }}>
        <TableContainer sx={{ width: "80%", margin: "5px" }} component={Paper}>
          <Table size="small" aria-label="simple table">
            <TableHead sx={{ ...normalTableHeaderStyle }}>
              <TableRow sx={{ fontWeight: "bold" }}>
                <TableCell colSpan={2}>Flow Information</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              <TableRow>
                <TableCell>Flow State and Protocol</TableCell>
                <TableCell>
                  {flow.four_way_close_done ? "Closed" : "Active"}{" "}
                  {String(flow.key.ip_proto)}
                </TableCell>
              </TableRow>
              <TableRow>
                <TableCell>Remote Host</TableCell>
                <TableCell>{flow.remote_hostname}</TableCell>
              </TableRow>
              <TableRow>
                <TableCell>Remote IP + Port</TableCell>
                <TableCell>
                  {flow.key.remote_ip} {flow.key.remote_l4_port}
                </TableCell>
              </TableRow>
              <TableRow>
                <TableCell>Local IP + Port</TableCell>
                <TableCell>
                  {flow.key.local_ip} {flow.key.local_l4_port}
                </TableCell>
              </TableRow>
              <TableRow>
                <TableCell>Application(s)</TableCell>
                <TableCell>
                  {formatAssociatedApps(flow.associated_apps)}
                </TableCell>
              </TableRow>
              <TableRow>
                <TableCell>First Packet Seen</TableCell>
                <TableCell>
                  {new Date(
                    flow.start_tracking_time_ns / 1000000,
                  ).toLocaleString()}
                </TableCell>
              </TableRow>
              <TableRow>
                <TableCell>Last Packet Seen</TableCell>
                <TableCell>
                  {new Date(
                    flow.last_packet_time_ns / 1000000,
                  ).toLocaleString()}
                </TableCell>
              </TableRow>
              <TableRow>
                <TableCell>Flow Duration</TableCell>
                <TableCell>
                  {prettyPrintDuration(
                    flow.start_tracking_time_ns,
                    flow.last_packet_time_ns,
                  )}
                </TableCell>
              </TableRow>
            </TableBody>
          </Table>
        </TableContainer>
        <TableContainer sx={{ width: "80%", margin: "20px" }} component={Paper}>
          <Table size="small" aria-label="simple table">
            <TableHead sx={{ ...normalTableHeaderStyle }}>
              <TableRow sx={{ fontWeight: "bold" }}>
                <TableCell>Measurement</TableCell>
                <TableCell>Send</TableCell>
                <TableCell>Recv</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {getTxRxCell(
                flow,
                "Average last minute",
                "last_min_byte_rate",
                "Bytes/s",
                2,
              )}
              {getTxRxCell(
                flow,
                "Average last minute",
                "last_min_pkt_rate",
                "Pkts/s",
                2,
              )}
              {getTxRxCell(
                flow,
                "Retransmitted Bytes",
                "lost_bytes",
                "Bytes",
                2,
              )}
              {getTxRxCell(flow, "Total Bytes", "bytes", "Bytes", 2)}
              {getTxRxCell(flow, "Total Packets", "pkts", "Pkts", 2)}
              {getTxRxRttCell(flow, "RTT (mean)", "mean", "ms")}
              {getTxRxRttCell(flow, "RTT (max)", "max", "ms")}
              {getTxRxRttCell(flow, "RTT (min)", "min", "ms")}
            </TableBody>
          </Table>
        </TableContainer>
      </Stack>
    );
  }

  return (
    <div style={{ padding: 20 }}>
      <Stack spacing={2} direction="row">
        <SwitchHelper
          text={"Auto Refresh"}
          state={autoRefresh}
          updateFn={setAutoRefresh}
        />
        <Button
          variant="outlined"
          onClick={() => request_probe_flow(props.flow.key)}
        >
          Probe Flow
        </Button>
        <Button
          variant="outlined"
          onClick={() => request_ping_tree(props.flow.key)}
        >
          PingTree
        </Button>
        <Button variant="outlined" onClick={() => navigate(-1)}>
          Back
        </Button>
      </Stack>
      {props.flow ? (
        <div>
          {renderTxRxGraph(props.flow)}
          {renderProbeReport(props.flow)}
        </div>
      ) : (
        <div> Flow not found: Probably expired from the local cache </div>
      )}
    </div>
  );
};

// wrapper around FlowDetails when called by the loader
export const FlowDetailsByParam: React.FC = () => {
  const flow = useLoaderData() as ConnectionMeasurements;
  return <FlowDetails flow={flow} />;
};
