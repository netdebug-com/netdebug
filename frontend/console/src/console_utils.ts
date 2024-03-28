import { DataLoadingCallback } from "./common";
// Make rest calls back to the URL that served us the page
// This allows us to not worry about dev vs. prod URLs
export function get_rest_url(path: string): string {
  // e.g., "https://hostname:port"
  return window.location.origin + "/" + path;
}

// Modeled after common/data_loading::loadData
//
// Call with, e.g., '/api/test_api' and if we get 401/our session key
// didn't exist or expired, try to get a new session cookie via our login
// process by calling /api/login and then retry the specified route
// Example
/*
  const [organization, setOrganization] = useState<string | null>(null);
  useEffect(() => {
    loadDataWithAuth(
      "api/organization_info",
      (resp: DataLoadingState<PublicOrganizationInfo>) => {
        if (resp.isPending) {
          setOrganization("Pending...");
        } else if (resp.error) {
          setOrganization("Error: " + resp.error);
        } else {
          // once we've really got the org loaded, just print the name
          setOrganization(resp.data.name);
        }
      },
    );
  }, []);
  */
export function loadDataWithAuth<T>(
  route: string,
  cb: DataLoadingCallback<T>,
): void {
  fetchAndCheckResultWithAuth(route)
    .then((resp) => {
      if (resp) {
        return resp.json();
      } else {
        throw Error("Was handed an undefined response " + resp);
      }
    }) // prev call ensures this is StatusCode==200
    .then((json) => cb({ isPending: false, error: null, data: json }))
    .catch((err) => cb({ isPending: false, error: err, data: null }));
}

// Do a `fetch()` call, but if we get a 401, reauth and retry
// If we get a non-401, check the returned response and throw an error if
// the response code is not 401. Simplifies error handling
export async function fetchAndCheckResultWithAuth(
  url: string,
): Promise<Response> {
  return fetch(get_rest_url(url)).then((resp) => {
    if (resp.ok) {
      return resp;
    } else {
      if (resp.status == 401) {
        // no valid session cookie: try to get a new session cookie and retry route
        // if the user is logged in via clerk, then they will have a __session
        // cookie already set, so we just need to call the login API which translates
        // that into a netdebug session cookie (once we validate they have an account)
        console.log("Refreshing netdebug session token");
        return fetch(get_rest_url("api/login")).then((auth_resp) => {
          if (auth_resp.ok) {
            // got a new session token, retry route
            return fetch(get_rest_url(url)).then((resp2) => {
              if (!resp2.ok) {
                makeResponseError(
                  "Non-auth Error (2nd try) talking to ",
                  resp2,
                  url,
                );
              }
              return resp2;
            });
          } else {
            // failed to get the auth; report the error
            makeResponseError("Failed to re-authenticate to ", auth_resp, url);
          }
        });
      } else {
        // didn't get 200 or 401 from the original call, just report error
        makeResponseError("Non-auth Error talking to ", resp, url);
      }
    }
  });
}

function makeResponseError(explain: string, response: Response, url: string) {
  response.text().then((txt) => {
    const msg = explain + " " + url + " status=" + response.status + " " + txt;
    console.error(msg);
    throw new Error(msg);
  });
}
