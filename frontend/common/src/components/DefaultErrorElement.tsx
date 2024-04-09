import { isRouteErrorResponse, useRouteError } from "react-router";
import { ErrorMessage } from "./ErrorMessage";

export function DefaultErrorElement() {
  // useRouteError() will return whatever a load has thrown. Since JS allows one to
  // throw anything, not just `Error`. In particular, react-router will/can return an
  // `ErrorResponse` which essentially wraps a `fetch()` resposne but with the body resolved.
  // TODO: find out if we should use ErrorReponse for errors from our loaders
  const error = useRouteError();
  if (isRouteErrorResponse(error)) {
    // is this an ErrorResponse instance?
    let msg = error.status + ": " + error.statusText;
    if (error.data) {
      msg += error.data;
    }
    return <ErrorMessage msg={msg} />;
  } else if (error instanceof Error) {
    // A JS `Error`
    return <ErrorMessage msg={error.name + ": " + error.message} />;
  } else {
    // Who knows what's going on
    console.log("DefaultErrorElement", error);
    return <ErrorMessage msg={"Unknown Error"} />;
  }
}
