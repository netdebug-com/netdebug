import {
  ActionFunctionArgs,
  ParamParseKey,
  Params,
  useLoaderData,
  useParams,
} from "react-router";
import { fetchAndCheckResultWithAuth } from "../console_utils";

interface DeviceLoaderArgs extends ActionFunctionArgs {
  params: Params<ParamParseKey<string>>;
}

export const deviceFlowsLoader = async ({ params }: DeviceLoaderArgs) => {
  const url = "api/get_device_flows/" + params.uuid;
  const res = await fetchAndCheckResultWithAuth(url);
  return await res.json();
};
export function DeviceFlows() {
  const { uuid } = useParams();
  const device = useLoaderData() as string;
  return (
    <div>
      Placeholder until next diff!
      <h3> {uuid} </h3>
      <pre>{JSON.stringify(device)}</pre>
    </div>
  );
}
