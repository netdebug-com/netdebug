// check how long it's been since our last message and send now or later

import { MutableRefObject } from "react";
import { RateEstimator } from "./netdebug_types";

// depending on our SLAs
export function periodic_with_sla(
  label: string,
  timeout_id: MutableRefObject<NodeJS.Timeout>,
  last_send: MutableRefObject<number>,
  min: number,
  max: number,
  callback: () => void,
) {
  const send_delta = performance.now() - last_send.current;
  if (send_delta <= min) {
    timeout_id.current = setTimeout(callback, min - send_delta);
  } else {
    timeout_id.current = null;
    callback();
    if (send_delta > max) {
      console.warn(label + " reply delayed beyond SLA " + max + "ms");
    }
  }
}

export function rateEstimatorPrettyRate(
  rate: RateEstimator,
  unitSuffix: string,
): string {
  if (rate.estimate_rate_per_ns === null) {
    return "None";
  }
  const per_sec = rate.estimate_rate_per_ns * 1e9;
  const opts = {
    maximumFractionDigits: 1,
  };
  if (per_sec > 1e9) {
    return (per_sec / 1e9).toLocaleString(undefined, opts) + " G" + unitSuffix;
  } else if (per_sec > 1e6) {
    return (per_sec / 1e6).toLocaleString(undefined, opts) + " M" + unitSuffix;
  } else if (per_sec > 1e3) {
    return (per_sec / 1e3).toLocaleString(undefined, opts) + " K" + unitSuffix;
  } else {
    return per_sec.toLocaleString(undefined, opts) + " " + unitSuffix;
  }
}

// External style sheets are for loser...
export const headerStyle = {
  // Looks like MUI has a color palette and we can refer to these
  // colors :-)
  // https://mui.com/material-ui/customization/palette/
  backgroundColor: "primary.main",
  color: "primary.contrastText",
  fontWeight: "bold",
};

// Re-use the header style but a width
// See https://mui.com/system/getting-started/the-sx-prop/#sizing
// For an explanation of what the width means exactly.
// But values < 1.0 are translated into percent (0.5 -> 50%)
// Otherwise the unit is `px`
export function headerStyleWithWidth(width: number) {
  return { ...headerStyle, width: width, minWidth: width };
}
