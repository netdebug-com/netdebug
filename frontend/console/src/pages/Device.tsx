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
      <summary>{uuid} Raw JSON</summary>
      {renderDataLoadingState(deviceDetails, (d) => (
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

  return <div>{renderDeviceDetails(uuid, deviceDetails)}</div>;
}

export default Device;
