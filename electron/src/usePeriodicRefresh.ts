// TODO: In theory RevalidationState should have been re-exported by
// by react-router. But apparently not.... Gotta love UI
import { RevalidationState } from "@remix-run/router";
import { useRef } from "react";
import { useInterval } from "react-use";

// Sigh. useRevalidator() return type is not a named type, so we
// create and name one to keep this code neater
type RevalidatorType = {
  revalidate: () => void;
  state: RevalidationState;
};
// Helper hook to periodically refresh/reload the data via the loader.
export function usePeriodicRefresh(
  // If true, periodically refresh
  autoRefresh: boolean,
  // The validator to use for refreshes
  revalidator: RevalidatorType,
  // The interval in milliseconds on when to reload
  interval_ms: number,
  // A human readable description for log messages
  description?: string,
  // If set, the maximum time we want a reload to take. If it's longer than that,
  // log an error (just to the console)
  sla_max_time_ms?: number,
) {
  const lastRequestTime = useRef(null);
  useInterval(
    () => {
      if (revalidator.state === "idle") {
        // Only send a new request if the previous one has finished
        lastRequestTime.current = performance.now();
        revalidator.revalidate();
      } else {
        // We are still loading. Check if we have an SLA and if so, log a warning if
        // it's violated.
        if (
          sla_max_time_ms &&
          performance.now() - lastRequestTime.current > sla_max_time_ms
        ) {
          console.warn(
            (description ? description + ": " : "") + "Reloading took too long",
          );
        }
      }
    },
    autoRefresh ? interval_ms : null,
  );
}
