import { desktop_api_url } from "../utils";
import { useInterval } from "react-use";
import { useEffect, useState } from "react";
import { DataLoadingState, loadData as loadData } from "../common/data_loading";
import { ErrorMessage } from "../components/ErrorMessage";

function renderStringData(state: DataLoadingState<string>) {
  return (
    <>
      {state.isPending && "Loading ..."}
      {state.error && <ErrorMessage msg={"ERROR: " + state.error} />}
      {state.data && state.data}
    </>
  );
}

const Home: React.FC = () => {
  const [myIp, setMyIp] = useState(new DataLoadingState<string>());
  useEffect(() => {
    loadData(desktop_api_url("get_my_ip"), setMyIp);
  }, []);
  // Just for demo purposes: how to periodically reload the data.
  useInterval(() => {
    loadData(desktop_api_url("get_my_ip"), setMyIp);
  }, 5000);

  return (
    <div>
      <h1>Home Page</h1>
      My external IP Address is <em>{renderStringData(myIp)}</em>.
    </div>
  );
};

export default Home;
