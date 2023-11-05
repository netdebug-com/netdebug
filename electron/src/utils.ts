// check how long it's been since our last message and send now or later

import { MutableRefObject } from "react";

// depending on our SLAs
function periodic_with_sla(
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

// External style sheets are for loser...
const headerStyle = {
  backgroundColor: "#110099",
  color: "white",
  fontWeight: "bold",
};

export { periodic_with_sla, headerStyle };
