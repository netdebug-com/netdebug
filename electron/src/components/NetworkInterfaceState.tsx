import { ApexOptions } from "apexcharts";
import { NetworkInterfaceState } from "../netdebug_types";
import ReactApexChart from "react-apexcharts";
import { useTheme } from "@mui/material/styles";
import Table from "@mui/material/Table";
import TableBody from "@mui/material/TableBody";
import TableCell from "@mui/material/TableCell";
import TableContainer from "@mui/material/TableContainer";
import TableHead from "@mui/material/TableHead";
import TableRow from "@mui/material/TableRow";
import Paper from "@mui/material/Paper";
import Tabs from "@mui/material/Tabs";
import Tab from "@mui/material/Tab";
import Box from "@mui/material/Box";
import { useState } from "react";

// Re-usable components to show the detailed information in a flow
// Assumes we already have the corresponding connection measurement
// The 'FlowSummary' is a one-line description of the flow - suitable for a list, but it's clickable
// so that it can popover a more detailed analysys of that flow

function renderIps(name: string, ip_list: string[]) {
  if (ip_list.length == 1) {
    return (
      <div>
        {name}: {ip_list[0]}{" "}
      </div>
    );
  } else {
    return (
      <details>
        <summary>
          {" "}
          {name}s: {ip_list.length} addresses
        </summary>
        <ol>
          {ip_list.map((ip) => (
            <li key={ip}> {ip} </li>
          ))}
        </ol>
      </details>
    );
  }
}

// Take a network interface and return
// "Active (last <time>)" or
// "(Old - from <time> to <time>)"
function make_context_string(state: NetworkInterfaceState): string {
  if (state.end_time == null) {
    const seconds = Math.floor(
      (Date.now() - Date.parse(state.start_time)) / 1000,
    );
    return "Active (last " + seconds + " secs) ";
  } else {
    return (
      "(Old - from " +
      new Date(Date.parse(state.start_time)).toLocaleString() +
      " to " +
      new Date(Date.parse(state.end_time)).toLocaleString() +
      " ) "
    );
  }
}

function prettyBool(yes: boolean): string {
  return yes ? "Yes" : "No";
}

export const NetworkInterfaceStateComponent: React.FC<
  NetworkInterfaceStateProps
> = (props) => {
  const should_open = props.state.end_time == null;
  const context = make_context_string(props.state);
  // let date_str =
  return (
    <details open={should_open}>
      <summary>
        {context} :: Interface {props.state.interface_name}
      </summary>
      <TableContainer component={Paper}>
        <Table sx={{ minWidth: 650 }} aria-label="simple table">
          <TableHead>
            <TableRow>
              <TableCell>Interface IPs</TableCell>
              <TableCell align="right">Gateway IPs</TableCell>
              <TableCell align="right">Link?</TableCell>
              <TableCell align="right">Wireless?</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            <TableRow
              sx={{ "&:last-child td, &:last-child th": { border: 0 } }}
            >
              <TableCell component="th" scope="row">
                {renderIps("IP", props.state.interface_ips)}
              </TableCell>
              <TableCell align="right" component="th" scope="row">
                {renderIps("IP", props.state.gateways)}
              </TableCell>
              <TableCell align="right">
                {prettyBool(props.state.has_link)}
              </TableCell>
              <TableCell align="right">
                {prettyBool(props.state.is_wireless)}
              </TableCell>
            </TableRow>
          </TableBody>
        </Table>
      </TableContainer>
      <PingGraph state={props.state} ip_selector={IpVersionSelector.BOTH} />
    </details>
  );
};

export enum IpVersionSelector {
  IPV4_ONLY,
  IPV6_ONLY,
  BOTH,
}

export interface NetworkInterfaceStateProps {
  state: NetworkInterfaceState;
  ip_selector: IpVersionSelector;
}

interface PingStats {
  min: number;
  q1: number;
  median: number;
  q3: number;
  max: number;
  raw_rtts: number[];
  drop_count: number;
  missed_outgoing: number;
  total_non_missed_probes: number;
  total_probes: number;
}

/* Does this IP match the version specified ? */
function matchesSelector(ip: string, ip_selector: IpVersionSelector): boolean {
  if (ip_selector == IpVersionSelector.BOTH) {
    return true;
  } else {
    // HACK : use the ':' character to identify IPv6
    // seems like this should be accomplishable in fewer lines, but low ROI
    if (ip_selector == IpVersionSelector.IPV4_ONLY) {
      return !ip.includes(":");
    } else {
      return ip.includes(":");
    }
  }
}

export const PingGraph: React.FC<NetworkInterfaceStateProps> = (props) => {
  const theme = useTheme();
  const [value, setValue] = useState(0);

  // copied from https://mui.com/material-ui/react-tabs/
  const handleChange = (event: React.SyntheticEvent, newValue: number) => {
    setValue(newValue);
  };
  function a11yProps(index: number) {
    return {
      id: `simple-tab-${index}`,
      "aria-controls": `simple-tabpanel-${index}`,
    };
  }

  // Calculate a bunch of useful stats on the Ping information, per gateway
  function calcPingStats(state: NetworkInterfaceState): Map<string, PingStats> {
    const stats = new Map<string, PingStats>();
    Object.entries(state.gateways_ping).forEach(([gateway_ip, ping_info]) => {
      // which probes do we have both a valid sent and recv time?
      const good_replies = ping_info.historical_probes.filter(
        (probe) => !probe.dropped,
      );
      // which probes do we only have a recv time; this means that pcap was
      // overloaded and we got the reply, but not the outgoing send time stamp
      const missed_outgoing = ping_info.historical_probes.filter(
        (probe) =>
          probe.recv_time_utc_ns != null && probe.sent_time_utc_ns == null,
      );
      // TODO: this assumes that a missing recv_time is a 'dropped' probe; think about it...
      const drop_count =
        ping_info.historical_probes.length - good_replies.length;
      const rtts = good_replies.map((probe) => {
        // we've already checked that these are not-null
        // NOTE: need to use *_utc_ns forms because if we used a String,
        // then Date.parse(string) only resolves to milliseconds which isn't
        // sufficient here
        // divide by 1e6 to convert from NS to MS
        return (probe.recv_time_utc_ns - probe.sent_time_utc_ns) / 1e6;
      });
      // @%$*(&@! javascript; the default sort() is "convert to string and sort by ASCII"
      // so "100" would come before "3".  FIX: pass an explicit sort function for numbers
      rtts.sort((a, b) => a - b);

      const ping_stats = {
        raw_rtts: rtts,
        min: rtts[0],
        q1: rtts[Math.floor(rtts.length / 4)],
        median: rtts[Math.floor(rtts.length / 2)],
        q3: rtts[Math.floor((3 * rtts.length) / 4)],
        max: rtts[rtts.length - 1],
        missed_outgoing: missed_outgoing.length,
        drop_count: drop_count,
        total_non_missed_probes:
          ping_info.historical_probes.length - missed_outgoing.length,
        total_probes: ping_info.historical_probes.length,
      };
      stats.set(gateway_ip, ping_stats);
    });
    return stats;
  }

  function getBoxplotData(
    pingData: Map<string, PingStats>,
    ip_selector: IpVersionSelector,
  ) {
    const rtt_data = Array.from(pingData)
      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      .filter(([gateway_ip, _]) => matchesSelector(gateway_ip, ip_selector))
      .map(([gateway_ip, ping_stats]) => {
        if (
          ping_stats.min > ping_stats.q1 ||
          ping_stats.q1 > ping_stats.median ||
          ping_stats.median > ping_stats.q3 ||
          ping_stats.q3 > ping_stats.max
        ) {
          console.error("Busting ping stats: ", ping_stats);
        }
        return {
          x: gateway_ip,
          y: [
            ping_stats.min,
            ping_stats.q1,
            ping_stats.median,
            ping_stats.q3,
            ping_stats.max,
          ],
        };
      });

    if (pingData.size != 0) {
      return [
        {
          type: "boxPlot",
          data: rtt_data,
        },
      ];
    } else {
      return [];
    }
  }

  function getBoxplotOptions(
    pingData: Map<string, PingStats>,
    ip_selector: IpVersionSelector,
  ): ApexOptions {
    let total_packets = 0;
    let dropped_packets = 0;
    Array.from(pingData)
      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      .filter(([gateway_ip, _]) => matchesSelector(gateway_ip, ip_selector))
      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      .forEach(([_, pingStats]) => {
        total_packets += pingStats.total_non_missed_probes;
        dropped_packets += pingStats.drop_count;
      });
    const annotations =
      pingData.size != 0
        ? {}
        : {
            yaxis: [
              {
                x: 1,
                y: 1,
                borderColor: "#000",
                fillColor: "#FEB019",
                opacity: 0.2,
                label: {
                  borderColor: "#333",
                  style: {
                    fontSize: "30px",
                    color: "#333",
                    background: "#FEB019",
                  },
                  text:
                    "No " +
                    prettyPrintIpSelector(ip_selector) +
                    " default routers found!!",
                },
              },
            ],
          };
    const percent_dropped_packets =
      pingData.size == 0
        ? 100 // no routers means 100% packet loss, not zero
        : total_packets == 0
        ? 0
        : (100 * dropped_packets) / total_packets;
    // is this really how to format to 2 decimal places in javascript?
    const percent_dropped_packets_pretty = (
      Math.round(percent_dropped_packets * 100) / 100
    ).toFixed(2);
    return {
      chart: {
        type: "boxPlot",
        animations: {
          enabled: false,
        },
      },
      annotations: annotations,
      legend: {
        show: true,
      },
      title: {
        text:
          "RTT to Local Gateways (ms) -- " +
          percent_dropped_packets_pretty +
          "% packet loss",
        align: "left",
      },
      xaxis: {
        title: {
          text: "Round-Trip Time (milliseconds)",
          style: {
            fontSize: "14px",
          },
        },
        // min: 0,
      },
      yaxis: {
        /* looks like ass, overlapping the axis
        labels: {
          rotate: 90,
          offsetX: 100,
          offsetY: -50,
        },
        */
      },
      plotOptions: {
        bar: {
          horizontal: true,
        },
        boxPlot: {
          colors: {
            // import the colors from the MUI theme
            upper: theme.palette.primary.main,
            lower: theme.palette.primary.light,
          },
        },
      },
    };
  }

  const pingStats = calcPingStats(props.state);
  const boxPlotHeight = 200;
  return (
    <Box sx={{ width: "100%" }}>
      <Box sx={{ borderBottom: 1, borderColor: "divider" }}>
        <Tabs
          value={value}
          onChange={handleChange}
          aria-label="basic tabs example"
        >
          <Tab label="IPv4" {...a11yProps(0)} />
          <Tab label="IPv6" {...a11yProps(1)} />
          <Tab label="Both" {...a11yProps(2)} />
        </Tabs>
      </Box>
      <CustomTabPanel value={value} index={0}>
        <ReactApexChart
          options={getBoxplotOptions(pingStats, IpVersionSelector.IPV4_ONLY)}
          series={getBoxplotData(pingStats, IpVersionSelector.IPV4_ONLY)}
          type="boxPlot"
          height={boxPlotHeight}
        />
      </CustomTabPanel>
      <CustomTabPanel value={value} index={1}>
        <ReactApexChart
          options={getBoxplotOptions(pingStats, IpVersionSelector.IPV6_ONLY)}
          series={getBoxplotData(pingStats, IpVersionSelector.IPV6_ONLY)}
          type="boxPlot"
          height={boxPlotHeight}
        />
      </CustomTabPanel>
      <CustomTabPanel value={value} index={2}>
        <ReactApexChart
          options={getBoxplotOptions(pingStats, IpVersionSelector.BOTH)}
          series={getBoxplotData(pingStats, IpVersionSelector.BOTH)}
          type="boxPlot"
          height={boxPlotHeight}
        />
      </CustomTabPanel>
    </Box>
  );
};

// copied from https://mui.com/material-ui/react-tabs/
interface TabPanelProps {
  children?: React.ReactNode;
  index: number;
  value: number;
}

function CustomTabPanel(props: TabPanelProps) {
  const { children, value, index, ...other } = props;

  return (
    <div
      role="tabpanel"
      hidden={value !== index}
      id={`simple-tabpanel-${index}`}
      aria-labelledby={`simple-tab-${index}`}
      {...other}
    >
      {value === index && <Box sx={{ p: 3 }}>{children}</Box>}
    </div>
  );
}

// Turn an IpSelector into reasonable text
function prettyPrintIpSelector(ip_selector: IpVersionSelector) {
  if (ip_selector == IpVersionSelector.BOTH) {
    return "IPv4 or IPv6";
  } else if (ip_selector == IpVersionSelector.IPV4_ONLY) {
    return "IPv4";
  } else if (ip_selector == IpVersionSelector.IPV6_ONLY) {
    return "IPv6";
  } else {
    return "FIXME: unknown IpSelector!?";
  }
}
