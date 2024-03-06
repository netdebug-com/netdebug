import React from "react";
import { desktop_api_url } from "@netdebug/common";
import { aggregateStatEntryDefaultSortFn } from "@netdebug/common";
import { fetchAndCheckResult } from "@netdebug/common";
import { AggregatedFlows } from "@netdebug/common";

export const flowsByApplicationLoader = async () => {
  const res = await fetchAndCheckResult(desktop_api_url("get_app_flows"));
  return res.json().then(aggregateStatEntryDefaultSortFn);
};

const FlowsByDnsDomain: React.FC = () => {
  return (
    <AggregatedFlows
      headerName={"Application"}
      expectedKind={"Application"}
      reload_interval_ms={1000}
      max_reload_time_ms={2000}
    />
  );
};

export default FlowsByDnsDomain;
