import { NetworkInterfaceState } from "../netdebug_types";
import { Bar } from "react-chartjs-2";

import {
  Chart as ChartJS,
  CategoryScale,
  PointElement,
  LinearScale,
  Tooltip,
  Legend,
  Colors,
  LineElement,
  Title,
  BarElement,
} from "chart.js";

ChartJS.register(
  BarElement,
  CategoryScale,
  PointElement,
  LinearScale,
  Tooltip,
  Legend,
  Colors,
  LineElement,
  Title,
);

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

function prettyBool(yes: boolean): string {
  return yes ? "Yes" : "No";
}

export const NetworkInterfaceStateComponent: React.FC<
  NetworkInterfaceStateProps
> = (props) => {
  const should_open = props.state.end_time == null;
  // let date_str =
  return (
    <details open={should_open}>
      <summary>Interface {props.state.interface_name}</summary>
      <ul>
        <li> {renderIps("Interface IP", props.state.interface_ips)}</li>
        <li> {renderIps("Gateway IP", props.state.gateways)}</li>
        <li> hasLink={prettyBool(props.state.has_link)}</li>
        <li> isWireless={prettyBool(props.state.is_wireless)}</li>
        <li> TODO: list time in a pretty way </li>
      </ul>
      <PingGraph state={props.state} />
    </details>
  );
};

export interface NetworkInterfaceStateProps {
  state: NetworkInterfaceState;
}

interface PingStats {
  min: number;
  max: number;
  p25: number;
  p50: number;
  p75: number;
  drop_count: number;
  missed_outgoing: number;
  total_non_missed_probes: number;
  total_probes: number;
}

export const PingGraph: React.FC<NetworkInterfaceStateProps> = (props) => {
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
      rtts.sort();

      const ping_stats = {
        min: rtts[0],
        max: rtts[rtts.length - 1],
        p25: rtts[Math.floor(rtts.length / 4)],
        p50: rtts[Math.floor(rtts.length / 2)],
        p75: rtts[Math.floor((3 * rtts.length) / 4)],
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

  /* Plot a stacked barchat for each gateway vs. their rtts
   * TODO: plot drops as well
   */

  function getChartjsData(state: NetworkInterfaceState) {
    const stats = calcPingStats(state);
    const rtt_data = Array.from(stats).map(([gateway_ip, ping_stats]) => {
      const d = {
        x: gateway_ip,
        // chartjs expects with stacked graphs that each value it the delta, not the
        // total, so we have to calc the deltas from each one
        min: ping_stats.min,
        p25: ping_stats.p25 - ping_stats.min,
        p50: ping_stats.p50 - ping_stats.p25,
        p75: ping_stats.p75 - ping_stats.p50,
        max: ping_stats.max - ping_stats.p75,
      };
      return d;
    });
    // the object formats for stacked bar graphs is really funky
    const datasets = [
      {
        label: "Min Rtt (ms)",
        data: rtt_data,
        parsing: {
          yAxisKey: "min",
        },
      },
      {
        label: "Some Rtts (p25)",
        data: rtt_data,
        parsing: {
          yAxisKey: "p25",
        },
      },
      {
        label: "Typical Rtts (p50)",
        data: rtt_data,
        parsing: {
          yAxisKey: "p50",
        },
      },
      {
        label: "Most Rtts (p75)",
        data: rtt_data,
        parsing: {
          yAxisKey: "p75",
        },
      },
      {
        label: "Max Rtt (ms)",
        data: rtt_data,
        parsing: {
          yAxisKey: "max",
        },
      },
    ];
    return {
      labels: Object.keys(stats), // each gateway_ip
      datasets: datasets,
    };
  }
  function getChartOptions() {
    const opts = {
      scales: {
        x: {
          stacked: true,
        },
        y: {
          stacked: true,
          title: {
            display: true,
            text: "RTT to Gateway (milliseconds)",
          },
        },
      },
    };
    return opts;
  }

  return (
    <div>
      <Bar data={getChartjsData(props.state)} options={getChartOptions()} />
    </div>
  );
};
