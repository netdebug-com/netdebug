import { useRouteError } from "react-router";

export function DefaultErrorElement() {
  // useRouteError() will return whatever a load has thrown. Since JS allows one to
  // throw anything, not just `Error` instance we could in theory get something other
  // than an error instance. But lets ignore that for now
  const error = useRouteError() as Error;
  return (
    <div style={{ color: "red", fontWeight: "bold" }}>
      {error.name + ": " + error.message}
    </div>
  );
}
