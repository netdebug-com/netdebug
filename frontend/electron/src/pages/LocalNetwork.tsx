import React, { useState } from "react";
import { SwitchHelper } from "../common/components/SwitchHelper";
import { desktop_api_url } from "../common/utils";
import { useLoaderData, useRevalidator } from "react-router";
import { usePeriodicRefresh } from "../common/hooks/usePeriodicRefresh";
import { fetchAndCheckResult } from "../common/data_loading";
import { NetworkInterfaceState } from "../common/netdebug_types";
import {
  IpVersionSelector,
  NetworkInterfaceStateComponent,
} from "../common/components/NetworkInterfaceState";

export const localNetworkLoader = async () => {
  const res = await fetchAndCheckResult(
    desktop_api_url("get_system_network_history"),
  );
  return res.json();
};

const RELOAD_INTERVAL_MS = 200;
const MAX_RELOAD_TIME = 1000;

function getCurrentState(states: NetworkInterfaceState[]) {
  return states.find((s) => s.end_time === null) || null;
}

const LocalNetwork: React.FC = () => {
  const networkInterfaceStates = useLoaderData() as NetworkInterfaceState[];
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [expandedState, setExpandedState] = useState<string | null>(
    getCurrentState(networkInterfaceStates)?.start_time,
  );

  // lets us re-fetch the data.
  const revalidator = useRevalidator();
  usePeriodicRefresh(
    autoRefresh,
    revalidator,
    RELOAD_INTERVAL_MS,
    "LocalNetwork",
    MAX_RELOAD_TIME,
  );

  return (
    <>
      <SwitchHelper
        text={"Auto Refresh"}
        state={autoRefresh}
        updateFn={setAutoRefresh}
      />
      <div>
        {networkInterfaceStates
          .map((state) => {
            return (
              <NetworkInterfaceStateComponent
                key={state.start_time}
                state={state}
                isExpanded={expandedState === state.start_time}
                expandedChangeCb={(event: React.SyntheticEvent, isExpanded) => {
                  isExpanded
                    ? setExpandedState(state.start_time)
                    : setExpandedState(null);
                }}
                ip_selector={IpVersionSelector.BOTH}
              />
            );
          })
          .reverse()}
      </div>
    </>
  );
};

export default LocalNetwork;
