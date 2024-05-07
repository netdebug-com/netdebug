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
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Title,
  Tooltip,
  Legend,
  TimeScale,
  Colors,
  TimeSeriesScale,
  ChartOptions,
} from "chart.js";
import "chartjs-adapter-date-fns";
import { Line } from "react-chartjs-2";

// weird ChartJs magic... TODO: figure it out...
ChartJS.register(
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Tooltip,
  Legend,
  CategoryScale,
  Title,
  TimeScale,
  TimeSeriesScale,
  Colors,
);

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

function generateTimeSeriesChartOptions(): ChartOptions<"line"> {
  return {
    scales: {
      x: {
        type: "time",
        time: {
          unit: "hour",
        },
      },
      /*
      y: {
        max: 1000,
      },
      */
    },
    responsive: true,
    plugins: {
      legend: {
        position: "top" as const,
      },
      title: {
        display: true,
        text: "First Router Ping Times",
      },
      colors: {
        enabled: true,
        forceOverride: true,
      },
    },
  };
}

function generateTimeSeriesChartData(
  firstHopTimeSeries: DataLoadingState<Array<Array<FirstHopTimeSeriesData>>>,
) {
  if (!firstHopTimeSeries.data) {
    if (firstHopTimeSeries.error) {
      console.warn("Error: ", +firstHopTimeSeries.error);
    }
    return { datasets: [] }; // empty if no data yet
  }
  // else data is loaded
  // TODO: outer array for p50, p99, etc.
  const p50_series = firstHopTimeSeries.data.map(
    (intf: Array<FirstHopTimeSeriesData>) => {
      const series_data = intf.map((ping_data: FirstHopTimeSeriesData) => ({
        x: ping_data.time,
        y: ping_data.aggregate_ping_data.rtt_p50_ns / 1e6, // 1e6 : ns to ms conversion
      }));
      return {
        label: intf[0].interface_name + " p50",
        data: series_data,
      };
    },
  );
  const p99_series = firstHopTimeSeries.data.map(
    (intf: Array<FirstHopTimeSeriesData>) => {
      const series_data = intf.map((ping_data: FirstHopTimeSeriesData) => ({
        x: ping_data.time,
        y: ping_data.aggregate_ping_data.rtt_p99_ns / 1e6, // 1e6 : ns to ms conversion
      }));
      return {
        label: intf[0].interface_name + " p99",
        data: series_data,
      };
    },
  );
  return {
    datasets: [p50_series, p99_series].flat(),
  };
}

function renderFirstHopTimeSeries(
  uuid: string,
  firstHopTimeSeries: DataLoadingState<Array<Array<FirstHopTimeSeriesData>>>,
): JSX.Element {
  const time_series_data = generateTimeSeriesChartData(firstHopTimeSeries);
  console.log(
    "TimeSeries Data : #labels=",
    time_series_data.datasets.map((d) => d.label),
  );
  let count = 0;
  time_series_data.datasets.forEach((d) => {
    count += d.data.length;
    console.log(
      "TimeSeries Data: label " + d.label + " :: points=" + d.data.length,
    );
  });
  console.log("Time Series total data points graphed: " + count);
  return (
    <div>
      <Line
        options={generateTimeSeriesChartOptions()}
        data={time_series_data}
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
