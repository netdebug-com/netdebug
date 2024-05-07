import {
  ActionFunctionArgs,
  ParamParseKey,
  Params,
  useParams,
} from "react-router";
import {
  fetchAndCheckResultWithAuth,
  loadDataWithAuth,
} from "../console_utils";
import {
  DataLoadingState,
  FirstHopTimeSeriesData,
  PublicDeviceDetails,
  renderDataLoadingState,
} from "../common";
import { useEffect, useState } from "react";
import ReactApexChart from "react-apexcharts";

interface DeviceLoaderArgs extends ActionFunctionArgs {
  params: Params<ParamParseKey<string>>;
}

export const deviceLoader = async ({ params }: DeviceLoaderArgs) => {
  const url = "api/get_device/" + params.uuid;
  const res = await fetchAndCheckResultWithAuth(url);
  return await res.json();
};

function renderDeviceDetails(
  uuid: string,
  deviceDetails: DataLoadingState<PublicDeviceDetails>,
): JSX.Element {
  return (
    <details>
      <summary>Device Details for {uuid} </summary>
      {renderDataLoadingState(deviceDetails, (d) => (
        <pre>{JSON.stringify(d, null, 2)}</pre>
      ))}
    </details>
  );
}

function generateTimeSeriesChartOptions(): ApexCharts.ApexOptions {
  return {
    chart: {
      type: "area",
      stacked: false,
      height: 350,
      zoom: {
        type: "x",
        enabled: true, // this is what allows autozooming of time
        autoScaleYaxis: true,
      },
      toolbar: {
        autoSelected: "zoom",
      },
    },
    dataLabels: {
      enabled: false,
    },
    markers: {
      size: 0,
    },
    title: {
      text: "Latency to First-Hop Router",
      align: "left",
    },
    fill: {
      type: "gradient",
      gradient: {
        shadeIntensity: 1,
        inverseColors: false,
        opacityFrom: 0.5,
        opacityTo: 0,
        stops: [0, 90, 100],
      },
    },
    yaxis: {
      labels: {
        formatter: function (val) {
          return (val / 1000000).toFixed(0); // map ns to ms
        },
      },
      title: {
        text: "Latency (milliseconds)",
      },
    },
    xaxis: {
      type: "datetime", // I think this is the magic that says interpret the 'x' value as seconds from the EPOCH
      // ApexCharts documentation isn't super clear here
    },
    tooltip: {
      shared: false,
      y: {
        formatter: function (val) {
          return (val / 1000000).toFixed(2); // map ns to ms for the tooltip
        },
      },
    },
  };
}

interface PingDataPoint {
  x: string;
  y: number;
}

// eslint-disable-next-line @typescript-eslint/no-unused-vars
function generateTimeSeriesChartDataMerged(
  firstHopTimeSeries: DataLoadingState<Array<Array<FirstHopTimeSeriesData>>>,
): ApexAxisChartSeries | ApexNonAxisChartSeries {
  // TODO: outer array for p50, p99, etc.
  if (!firstHopTimeSeries.data) {
    return []; // still loading or error
  }
  // else data is loaded
  const p50_map = new Map<string, Array<PingDataPoint>>();
  firstHopTimeSeries.data.forEach((intf: Array<FirstHopTimeSeriesData>) => {
    const series_data = intf.map((ping_data: FirstHopTimeSeriesData) => ({
      x: ping_data.time,
      y: ping_data.aggregate_ping_data.rtt_p50_ns,
    }));
    const name = intf[0].interface_name + " p50";
    if (p50_map.has(name)) {
      p50_map.get(name).push(...series_data);
    } else {
      p50_map.set(name, series_data);
    }
  });
  const p99_map = new Map<string, Array<PingDataPoint>>();
  firstHopTimeSeries.data.forEach((intf: Array<FirstHopTimeSeriesData>) => {
    const series_data = intf.map((ping_data: FirstHopTimeSeriesData) => ({
      x: ping_data.time,
      y: ping_data.aggregate_ping_data.rtt_p99_ns,
    }));
    const name = intf[0].interface_name + " p99";
    if (p99_map.has(name)) {
      p99_map.get(name).push(...series_data);
    } else {
      p99_map.set(name, series_data);
    }
  });
  const p50_series = Array.from(
    p50_map,
    ([k, v]: [string, Array<PingDataPoint>]) => ({ name: k, data: v }),
  );
  const p99_series = Array.from(
    p99_map,
    ([k, v]: [string, Array<PingDataPoint>]) => ({ name: k, data: v }),
  );
  return [p50_series, p99_series].flat();
}

function generateTimeSeriesChartData(
  firstHopTimeSeries: DataLoadingState<Array<Array<FirstHopTimeSeriesData>>>,
): ApexAxisChartSeries | ApexNonAxisChartSeries {
  // TODO: outer array for p50, p99, etc.
  if (!firstHopTimeSeries.data) {
    return []; // still loading or error
  }
  // else data is loaded
  const p50_series = firstHopTimeSeries.data.map(
    (intf: Array<FirstHopTimeSeriesData>) => {
      const series_data = intf.map((ping_data: FirstHopTimeSeriesData) => ({
        x: ping_data.time,
        y: ping_data.aggregate_ping_data.rtt_p50_ns,
      }));
      return {
        name: intf[0].interface_name + " p50",
        data: series_data,
      };
    },
  );
  const p99_series = firstHopTimeSeries.data.map(
    (intf: Array<FirstHopTimeSeriesData>) => {
      const series_data = intf.map((ping_data: FirstHopTimeSeriesData) => ({
        x: ping_data.time,
        y: ping_data.aggregate_ping_data.rtt_p99_ns,
      }));
      return {
        name: intf[0].interface_name + " p99",
        data: series_data,
      };
    },
  );
  return [p50_series, p99_series].flat();
}

function renderFirstHopTimeSeries(
  uuid: string,
  firstHopTimeSeries: DataLoadingState<Array<Array<FirstHopTimeSeriesData>>>,
): JSX.Element {
  const time_series_data = generateTimeSeriesChartData(firstHopTimeSeries);
  console.log(
    "TimeSeries Data : #labels=",
    time_series_data.map((d) => d.name),
  );
  let count = 0;
  time_series_data.forEach((d) => {
    count += d.data.length;
    console.log(
      "TimeSeries Data: label " + d.name + " :: points=" + d.data.length,
    );
  });
  console.log("Time Series total data points graphed: " + count);
  return (
    <div>
      <ReactApexChart
        options={generateTimeSeriesChartOptions()}
        series={time_series_data}
        type="area"
        height={350}
      />

      <details>
        <summary>First-Router Time Series for {uuid} </summary>
        {renderDataLoadingState(firstHopTimeSeries, (d) => (
          <pre>{JSON.stringify(d, null, 2)}</pre>
        ))}
      </details>
    </div>
  );
}

export function Device() {
  const { uuid } = useParams();
  const [deviceDetails, setDeviceDetails] = useState(
    new DataLoadingState<PublicDeviceDetails>(),
  );
  useEffect(() => {
    loadDataWithAuth("api/get_device/" + uuid, setDeviceDetails);
  }, [uuid]);

  const [firstHopTimeSeries, setFirstHopTimeSeries] = useState(
    new DataLoadingState<Array<Array<FirstHopTimeSeriesData>>>(),
  );
  useEffect(() => {
    loadDataWithAuth(
      "api/get_first_hop_time_series/" + uuid,
      setFirstHopTimeSeries,
    );
  }, [uuid]);

  return (
    <div>
      {renderFirstHopTimeSeries(uuid, firstHopTimeSeries)}
      {renderDeviceDetails(uuid, deviceDetails)}
    </div>
  );
}

export default Device;
