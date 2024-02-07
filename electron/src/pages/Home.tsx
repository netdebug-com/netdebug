import { desktop_api_url } from "../utils";
import { useInterval } from "react-use";
import { useEffect, useState } from "react";
import { DataLoadingState, loadData as loadData } from "../common/data_loading";
import { ErrorMessage } from "../components/ErrorMessage";
import Stack from "@mui/material/Stack";
import Box from "@mui/material/Box";
import Paper from "@mui/material/Paper";
import { styled } from "@mui/material/styles";
import { ChartJsBandwidth, NetworkInterfaceState } from "../netdebug_types";
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
import {
  IpVersionSelector,
  PingGraph,
} from "../components/NetworkInterfaceState";
import { getChartOptions, getChartScale, getChartjsData } from "./Bandwidth";
// needed for anything ChartJS to work
ChartJS.register(
  PointElement,
  LinearScale,
  Tooltip,
  Legend,
  Colors,
  LineElement,
  Title,
);

function renderIpStringData(state: DataLoadingState<string>) {
  return (
    <>
      {state.isPending && "Loading ..."}
      {state.error && <ErrorMessage msg={"ERROR: " + state.error} />}
      {state.data && state.data.replace(/^::ffff:/, "")}
    </>
  );
}

const Item = styled(Paper)(({ theme }) => ({
  backgroundColor: theme.palette.mode === "dark" ? "#1A2027" : "#fff",
  ...theme.typography.body2,
  padding: theme.spacing(1),
  textAlign: "center",
  color: theme.palette.text.secondary,
}));

const Home: React.FC = () => {
  // myIp state
  const [myIp, setMyIp] = useState(new DataLoadingState<string>());
  useEffect(() => {
    loadData(desktop_api_url("get_my_ip"), setMyIp);
  }, []);
  useInterval(() => {
    loadData(desktop_api_url("get_my_ip"), setMyIp);
  }, 5000);
  // bandwidth state
  const [bandwidth, setBandwidth] = useState<ChartJsBandwidth | null>(null);
  useEffect(() => {
    loadData<ChartJsBandwidth[]>(
      desktop_api_url("get_aggregate_bandwidth"),
      setPerMinuteBandwidth,
    );
  }, []);
  useInterval(() => {
    loadData(desktop_api_url("get_aggregate_bandwidth"), setPerMinuteBandwidth);
  }, 500);
  // network gateway ping state
  const [networkInterfaceState, setNetworkInterfaceState] =
    useState<NetworkInterfaceState | null>(null);
  useEffect(() => {
    loadData<NetworkInterfaceState[]>(
      desktop_api_url("get_system_network_history"),
      setFirstNetworkInterfaceState,
    );
  }, []);
  useInterval(() => {
    loadData(
      desktop_api_url("get_system_network_history"),
      setFirstNetworkInterfaceState,
    );
  }, 1000);

  function setPerMinuteBandwidth(bw: DataLoadingState<ChartJsBandwidth[]>) {
    if (bw.data != null) {
      setBandwidth(bw.data[1]); // 0 is 5 second, 1 is OneMinute, 2 is One Hour
    }
  }
  function setFirstNetworkInterfaceState(
    x: DataLoadingState<NetworkInterfaceState[]>,
  ) {
    if (x.data != null) {
      setNetworkInterfaceState(x.data[0]);
    }
  }

  return (
    <Box sx={{ width: "100%" }}>
      <Stack spacing={2} useFlexGap>
        <Item>
          <Stack spacing={2} direction="row" useFlexGap>
            <Item sx={{ width: "45%" }}>
              <b>
                <em>What's New</em>{" "}
              </b>
              <ul>
                <li>Coming soon!</li>
              </ul>
            </Item>
            <Item sx={{ width: "45%" }}>
              <b>
                <em>Insights:</em>
              </b>
              <ul>
                <li>
                  My external IP Address is <em>{renderIpStringData(myIp)}</em>.{" "}
                </li>
              </ul>
            </Item>
          </Stack>
        </Item>
        <Item>
          <div
            // Layhout hackery. There's probably a better way to do this, but this
            // looks decent enough for now and will do.
            style={{ position: "relative", height: "25vh", padding: "1vh" }}
          >
            {bandwidth && (
              <Scatter
                data={getChartjsData(bandwidth, getChartScale(bandwidth))}
                options={getChartOptions(bandwidth, getChartScale(bandwidth))}
              />
            )}
            <hr />
          </div>
        </Item>
        <Item>
          {networkInterfaceState && (
            <PingGraph
              state={networkInterfaceState}
              // for the Home page, only show IPv4
              ip_selector={IpVersionSelector.IPV4_ONLY}
            />
          )}
        </Item>
      </Stack>
    </Box>
  );
};

export default Home;
