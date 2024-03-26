import { useAuth } from "@clerk/clerk-react";
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
  fetch(get_rest_url(route))
    .then((resp) => {
      if (resp.ok) {
        return resp.json();
      } else {
        if (resp.status == 401) {
          // no valid session cookie: try to get a new session cookie and retry route
          const auth = useAuth(); // magic from Clerk.com
          auth.getToken().then((jwt) => {
            fetch(get_rest_url("api/login?clerk_jwt=" + jwt)).then(
              (auth_resp) => {
                if (auth_resp.ok) {
                  // got a new session token, retry route
                  return fetch(get_rest_url(route));
                } else {
                  // failed to get the auth; report the error
                  throw Error(
                    "Failed to re-authenticate to " +
                      get_rest_url(route) +
                      " status=" +
                      auth_resp.status +
                      " " +
                      auth_resp.text(),
                  );
                }
              },
            );
          });
        } else {
          // didn't get 200 or 401 from the original call, just report error
          throw Error(
            "Non-auth Error talking to " +
              get_rest_url(route) +
              " status=" +
              resp.status +
              " " +
              resp.text(),
          );
        }
      }
    })
    .then((json) => cb({ isPending: false, error: null, data: json }))
    .catch((err) => cb({ isPending: false, error: err, data: null }));
}
