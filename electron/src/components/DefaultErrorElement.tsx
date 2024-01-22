import { useRouteError } from "react-router";
import { ErrorMessage } from "./ErrorMessage";

export function DefaultErrorElement() {
  // useRouteError() will return whatever a load has thrown. Since JS allows one to
  // throw anything, not just `Error` instance we could in theory get something other
  // than an error instance. But lets ignore that for now
  const error = useRouteError() as Error;
  return <ErrorMessage msg={error.name + ": " + error.message} />;
}
