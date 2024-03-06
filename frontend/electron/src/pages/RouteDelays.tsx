import React, { ReactNode } from "react";
import {
  CongestedLink,
  CongestedLinksReply,
  CongestionLatencyPair,
  ConnectionKey,
  ConnectionMeasurements,
} from "@netdebug/common";
import TableContainer from "@mui/material/TableContainer";
import Paper from "@mui/material/Paper";
import Table from "@mui/material/Table";
import TableHead from "@mui/material/TableHead";
import TableRow from "@mui/material/TableRow";
import TableCell from "@mui/material/TableCell";
import {
  calcStyleByThreshold,
  desktop_api_url,
  headerStyle,
  headerStyleWithWidth,
  prettyPrintSiUnits,
} from "@netdebug/common";
import { FlowSummary } from "@netdebug/common";
import { useLoaderData } from "react-router";
import { fetchAndCheckResult } from "@netdebug/common";

function toFlowKey(key: ConnectionKey): string {
  return (
    key.local_ip +
    "_" +
    key.local_l4_port +
    "_::_" +
    key.remote_ip +
    "_" +
    key.remote_l4_port +
    "_::" +
    key.ip_proto
  );
}

function make_link_key(link: CongestedLink): string {
  return (
    link.key.src_ip +
    "..." +
    link.key.src_to_dst_hop_count +
    "..." +
    link.key.dst_ip
  );
}

function linkSortFnByDelay(a: CongestedLink, b: CongestedLink) {
  // TODO: make this variable in how we can sort it
  const a_delta = a.peak_latency_us - a.mean_latency_us;
  const b_delta = b.peak_latency_us - b.mean_latency_us;
  return b_delta - a_delta;
}

function flowSortFnByCongestion(
  a: CongestionLatencyPair,
  b: CongestionLatencyPair,
) {
  const a_delta = a.dst_rtt_us - a.src_rtt_us;
  const b_delta = b.dst_rtt_us - b.src_rtt_us;
  return b_delta - a_delta;
}

interface CongestionInfo {
  congestionSummary: Array<CongestedLink>;
  connectionMeasurements: Map<string, ConnectionMeasurements>;
}

export const routerDelayLoader = async () => {
  const res = await fetchAndCheckResult(desktop_api_url("get_congested_links"));
  return res.json().then((congested_links: CongestedLinksReply) => {
    const congestion_info: CongestionInfo = {
      congestionSummary: congested_links.congestion_summary.links,
      connectionMeasurements: new Map(
        congested_links.connection_measurements.map((m) => [
          toFlowKey(m.key),
          m,
        ]),
      ),
    };
    return congestion_info;
  });
};

const RouterDelays: React.FC = () => {
  const congestionInfo = useLoaderData() as CongestionInfo;

  /**
   *
   * @param link The congested link
   * @returns A collapsible summary of the flows that are in this link
   */
  const render_affected_flows = (
    link: CongestedLink,
    key2Measurements: Map<string, ConnectionMeasurements>,
  ): ReactNode => {
    return (
      <details>
        <summary>{link.latencies.length}</summary>
        <TableContainer component={Paper}>
          <Table
            sx={{ minWidth: "500px" }}
            size="small"
            aria-label="Table of Congested Flows"
          >
            <TableHead>
              <TableRow style={headerStyle}>
                <TableCell sx={headerStyleWithWidth(0.1)} align="left">
                  Congestion
                </TableCell>
                <TableCell sx={headerStyleWithWidth(0.9)} align="right">
                  Flow
                </TableCell>
              </TableRow>
              {link.latencies.sort(flowSortFnByCongestion).map((lat) => {
                const flowKey = toFlowKey(lat.connection_key);
                return (
                  <TableRow key={flowKey}>
                    <TableCell>
                      {prettyPrintSiUnits(
                        (lat.dst_rtt_us - lat.src_rtt_us) * 1e-6,
                        "s",
                        2,
                      )}
                    </TableCell>
                    <TableCell>
                      <FlowSummary flow={key2Measurements.get(flowKey)} />
                    </TableCell>
                  </TableRow>
                );
              })}
            </TableHead>
          </Table>
        </TableContainer>
      </details>
    );
  };

  return (
    <div>
      <h1>Router Delays</h1>
      Tracks the delay in RTT coming back from the router: congestion + router
      processing delay but apparently DOMINATED by processing delay... weird!
      Investigate later.
      <TableContainer component={Paper}>
        <Table
          sx={{ minWidth: 650 }}
          size="small"
          aria-label="Table of Connections"
        >
          <TableHead>
            <TableRow style={headerStyle}>
              <TableCell sx={headerStyleWithWidth(0.3)} align="left">
                TTL Distance
              </TableCell>
              <TableCell sx={headerStyleWithWidth(0.3)} align="left">
                Link
              </TableCell>
              <TableCell sx={headerStyleWithWidth(0.1)} align="right">
                Mean Latency
              </TableCell>
              <TableCell sx={headerStyleWithWidth(0.1)} align="right">
                Peak Latency
              </TableCell>
              <TableCell sx={headerStyleWithWidth(0.1)} align="right">
                Affected Flows
              </TableCell>
              <TableCell sx={headerStyleWithWidth(0.1)} align="right">
                Max Processing Delay
              </TableCell>
            </TableRow>
            {congestionInfo &&
              congestionInfo.congestionSummary
                .sort(linkSortFnByDelay)
                .map((link) => {
                  const linkKey = make_link_key(link);
                  const peak_mean_delta =
                    link.peak_latency_us - link.mean_latency_us;
                  return (
                    <TableRow key={linkKey}>
                      <TableCell>{link.key.src_hop_count}</TableCell>
                      <TableCell>{linkKey}</TableCell>
                      <TableCell align="right">
                        {prettyPrintSiUnits(
                          link.mean_latency_us * 1e-6,
                          "s",
                          2,
                        )}
                      </TableCell>
                      <TableCell align="right">
                        {prettyPrintSiUnits(
                          link.peak_latency_us * 1e-6,
                          "s",
                          2,
                        )}
                      </TableCell>
                      <TableCell align="right">
                        {render_affected_flows(
                          link,
                          congestionInfo.connectionMeasurements,
                        )}
                      </TableCell>
                      <TableCell
                        align="right"
                        // 10ms is yellow, 50ms is red
                        sx={calcStyleByThreshold(peak_mean_delta, 10000, 50000)}
                      >
                        +{prettyPrintSiUnits(peak_mean_delta * 1e-6, "s", 2)}
                      </TableCell>
                    </TableRow>
                  );
                })}
          </TableHead>
        </Table>
      </TableContainer>
    </div>
  );
};

export default RouterDelays;
