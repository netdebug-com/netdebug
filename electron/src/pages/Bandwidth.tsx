import React, { useState } from "react";
import { ChartJsBandwidth, ChartJsPoint } from "../netdebug_types";
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
import { SwitchHelper } from "../components/SwitchHelper";
import { desktop_api_url, getSiScale, prettyPrintSiUnits } from "../utils";
import { useLoaderData, useRevalidator } from "react-router";
import { usePeriodicRefresh } from "../usePeriodicRefresh";

ChartJS.register(
  PointElement,
  LinearScale,
  Tooltip,
  Legend,
  Colors,
  LineElement,
  Title,
);

function getChartjsData(bw: ChartJsBandwidth, scale: BwChartScale) {
  return {
    datasets: [
      {
        label: "Download Bandwidth",
        data: scaleAndTrimeTimeseries(bw.rx, scale),
      },
      {
        label: "Upload Bandwidth",
        data: scaleAndTrimeTimeseries(bw.tx, scale),
      },
    ],
  };
}

/// Helper struct  for scaling the raw values from the desktop process
type BwChartScale = {
  // the scale factor to use for the y-axis. Raw data points should be divided by this
  y_scale: number;
  // the SI suffix of the scaled y number (e.g., `M` for mega)
  y_suffix: string;
  // the scale factor to use for the x-axis (time). Raw data points should be divided by this
  time_scale: number;
  // the time unit of the scale time. either
  time_unit: "minutes" | "seconds";
};

function getChartScale(bw: ChartJsBandwidth): BwChartScale {
  const [y_scale, y_suffix] = getSiScale(bw.y_max_bps);
  return {
    y_scale: y_scale,
    y_suffix: y_suffix,
    // we use 120sec as the cutoff between displaying in seconds vs. minutes
    time_scale: bw.total_duration_sec > 120 ? 60 : 1,
    time_unit: bw.total_duration_sec > 120 ? "minutes" : "seconds",
  };
}

// Apply the scale factor to the timeseries and also trim the
// last datapoint. The last datapoint represents an incomplete bucket, so we should not
// display it.
function scaleAndTrimeTimeseries(
  points: ChartJsPoint[],
  scale: BwChartScale,
): ChartJsPoint[] {
  const ret = points.map(({ x, y }) => {
    return { x: x / scale.time_scale, y: y / scale.y_scale };
  });
  ret.pop();
  return ret;
}

function getChartOptions(bw: ChartJsBandwidth, scale: BwChartScale) {
  const opts = {
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
        text: bw.label,
      },
      tooltip: {
        callbacks: {
          // @ts-expect-error chartjs are too convoluted. No idea what type context should be
          label: (context) => {
            let label = context.dataset.label || "";
            if (context.parsed.x !== null) {
              label += `: ${-context.parsed.x} ${scale.time_unit} ago`;
            }
            if (context.parsed.y !== null) {
              label +=
                ": " +
                // scale y-axis back to Bit/s then apply the prettyPrintSiUnit function
                prettyPrintSiUnits(context.parsed.y * scale.y_scale, "Bit/s");
            }
            return label;
          },
        },
      },
    },
    scales: {
      x: {
        title: {
          display: true,
          text: scale.time_unit + " ago",
        },
        ticks: {
          callback: (t: number) => -t,
        },
        max: 0,
      },
      y: {
        title: {
          display: true,
          text: scale.y_suffix + "Bit/s",
        },
        suggestedMin: 0,
      },
    },
  };
  if (bw.total_duration_sec === 3600) {
    // For 1hr timescale: force the x-axis to start at -3600, i.e., 1hr ago
    // @ts-expect-error TS complains x.min isn't in the object literal
    opts.scales.x.min = -3600 / scale.time_unit;
  }
  return opts;
}

export const bandwidthLoader = async () => {
  const res = await fetch(desktop_api_url("get_aggregate_bandwidth"));
  // TODO: error handling
  return res.json();
};

const RELOAD_INTERVAL_MS = 200;
const MAX_RELOAD_TIME = 1000;

const Bandwidth: React.FC = () => {
  const bandwidthHist = useLoaderData() as ChartJsBandwidth[];
  const [autoRefresh, setAutoRefresh] = useState(true);

  // lets us re-fetch the data.
  const revalidator = useRevalidator();
  usePeriodicRefresh(
    autoRefresh,
    revalidator,
    RELOAD_INTERVAL_MS,
    "Bandwidth",
    MAX_RELOAD_TIME,
  );

  // Default font size is tiny. Lets make the chart readable.
  ChartJS.defaults.font.size = 16;

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
          const scale = getChartScale(bw);
          return (
            <div
              key={bw.label}
              // Layhout hackery. There's probably a better way to do this, but this
              // looks decent enough for now and will do.
              style={{ position: "relative", height: "25vh", padding: "1vh" }}
            >
              <Scatter
                key={bw.label}
                data={getChartjsData(bw, scale)}
                options={getChartOptions(bw, scale)}
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
