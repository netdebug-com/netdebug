import React, { useState } from "react";
import { useWebSocketGuiToServer } from "../useWebSocketGuiToServer";
import { ChartJsBandwidth } from "../netdebug_types";
import { Scatter } from "react-chartjs-2";
import {
  Chart as ChartJS,
  PointElement,
  LinearScale,
  Tooltip,
  Legend,
  Colors,
  LineElement,
  Title,
} from "chart.js";
import { SwitchHelper } from "../SwitchHelper";

ChartJS.register(
  PointElement,
  LinearScale,
  Tooltip,
  Legend,
  Colors,
  LineElement,
  Title,
);

function getChartjsData(bw: ChartJsBandwidth) {
  return {
    datasets: [
      { label: "Download Bandwidth", data: bw.rx },
      { label: "Upload Bandwidth", data: bw.tx },
    ],
  };
}

function formatBps(value: number /*, index: number*/) {
  const mbps = value / 1e6;
  return mbps.toString();
}

function formatTimeTicks(value: number) {
  return -value;
}

function getChartOptions(bw: ChartJsBandwidth, y_max_bps: number) {
  const title = bw.label;
  return {
    showLine: true,
    // make TS: happy: animation can be false or some other type but never `true` so
    // we need to add the `as const` type assertion to make TS happy.
    animation: false as const,
    // let us set our own width & height ==> need to disable maintainAspectRatio
    maintainAspectRatio: false,
    //aspectRation: 1,
    plugins: {
      title: {
        display: true,
        text: title,
      },
    },
    scales: {
      x: {
        title: {
          display: true,
          text: "seconds ago",
        },
        ticks: {
          callback: formatTimeTicks,
        },
      },
      y: {
        title: {
          display: true,
          text: "MBit/s",
        },
        suggestedMin: 0,
        // use the next integer Mbps value
        suggestedMax: 1e6 * Math.ceil(y_max_bps / 1e6),
        ticks: {
          callback: formatBps,
        },
      },
    },
  };
}

const Bandwidth: React.FC = () => {
  const [bandwidthHist, setBandwidthHist] = useState<ChartJsBandwidth[]>([]);
  const [autoRefresh, setAutoRefresh] = useState(true);
  useWebSocketGuiToServer({
    autoRefresh: autoRefresh,
    reqMsgType: { DumpAggregateCounters: [] },
    respMsgType: "DumpAggregateCountersReply",
    min_time_between_requests_ms: 500,
    max_time_between_requests_ms: 5000,
    responseCb: setBandwidthHist,
  });
  // Default font size is tiny. Lets make the chart readable.
  ChartJS.defaults.font.size = 16;
  const y_max_bps = Math.ceil(
    Math.max(...bandwidthHist.map((bw) => bw.y_max_bps)),
  );

  return (
    <>
      <h1>Bandwidth Page</h1>
      <SwitchHelper
        text={"Auto Refresh"}
        state={autoRefresh}
        updateFn={setAutoRefresh}
      />
      <div>
        {bandwidthHist.map((bw) => {
          return (
            <div
              key={bw.label}
              // Layhout hackery. There's probably a better way to do this, but this
              // looks decent enough for now and will do.
              style={{ position: "relative", height: "25vh", padding: "1vh" }}
            >
              <Scatter
                key={bw.label}
                data={getChartjsData(bw)}
                options={getChartOptions(bw, y_max_bps)}
              />
              <hr />
            </div>
          );
        })}
      </div>
    </>
  );
};

export default Bandwidth;
