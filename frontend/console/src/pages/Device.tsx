import {
  ActionFunctionArgs,
  ParamParseKey,
  Params,
  useLoaderData,
  useParams,
} from "react-router";
import { fetchAndCheckResultWithAuth } from "../console_utils";
import { PublicDeviceInfo } from "../common";

interface DeviceLoaderArgs extends ActionFunctionArgs {
  params: Params<ParamParseKey<string>>;
}

export const deviceLoader = async ({ params }: DeviceLoaderArgs) => {
  const url = "api/get_device/" + params.uuid;
  const res = await fetchAndCheckResultWithAuth(url);
  return await res.json();
};
export function Device() {
  const { uuid } = useParams();
  const device = useLoaderData() as PublicDeviceInfo;
  return (
    <div>
      Placeholder until next diff!
      <h3> {uuid} </h3>
      {device && JSON.stringify(device)}
    </div>
  );
}

export default Device;
