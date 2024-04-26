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

function renderFirstHopTimeSeries(
  uuid: string,
  firstHopTimeSeries: DataLoadingState<
    Map<string, Array<FirstHopTimeSeriesData>>
  >,
): JSX.Element {
  console.log("TimeSeries ", firstHopTimeSeries);
  return (
    <details>
      <summary>First-Router Time Series for {uuid} </summary>
      {renderDataLoadingState(firstHopTimeSeries, (d) => (
        <pre>{JSON.stringify(d, null, 2)}</pre>
      ))}
    </details>
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
    new DataLoadingState<Map<string, Array<FirstHopTimeSeriesData>>>(),
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
