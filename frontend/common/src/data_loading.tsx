import { ErrorMessage } from "./components/ErrorMessage";

// The state for loading data from an URL.
export class DataLoadingState<T> {
  // The deserialized object, if the data was fetched successfully
  // null otherwise
  data: T | null;
  // indicates if the loading is pending/in progress. Can be used
  // to reander a loading indicator.
  isPending: boolean;
  // If loading failed, contains an error message. If no error, it's
  // null
  error: string | null;

  constructor() {
    this.data = null;
    this.isPending = true;
    this.error = null;
  }
}

export type DataLoadingCallback<T> = (x: DataLoadingState<T>) => void;

// The workhorse for loading data. Pass it an URL to fetch and a callback
// that should be called when the data has successfully loaded (or if
// there was an error).
// A common use-case is:
// .  const [myIp, setMyIp] = useState(new DataLoadingState<string>());
// .  useEffect(() => {
// .     loadData(desktop_api_url("get_my_ip"), setMyIp);
// .  }, []);
export function loadData<T>(url: string, cb: DataLoadingCallback<T>) {
  fetch(url)
    .then((res) => {
      if (!res.ok) {
        throw Error(
          "Failed to fetch data: " + res.status + " " + res.statusText,
        );
      }
      return res.json();
    })
    .then((d) => {
      cb({ isPending: false, error: null, data: d });
    })
    .catch((err) => {
      console.log(err.message);
      cb({ isPending: false, error: err.message, data: null });
    });
}

// Render a DataLoadingState.
// If the we are in `isPending`, then a `<div>Loading...</div>` is displayed
// If there was an error, a `<ErrorMessage>` component is rendered
// If the data loaded successfully, it is passed to a `renderer` callback
// that takes a non-null instance of T and returns a JSX.Element. E.g.,
//       <div>
//        {renderDataLoadingState(myIpState, (x) => (
//          <div style={{ color: "blue" }}>{x}</div>
//        ))}
//      </div>
export function renderDataLoadingState<T>(
  state: DataLoadingState<T>,
  renderer: (data: T) => JSX.Element,
) {
  if (state.isPending) {
    return <div> Loading... </div>;
  } else if (state.error) {
    return <ErrorMessage msg={"ERROR: " + state.error} />;
  } else if (state.data) {
    return <div> {renderer(state.data)} </div>;
  } else {
    return <div> Loaded (data is null!?)</div>;
  }
}

export function renderIpStringData(state: DataLoadingState<string>) {
  if (state.isPending) {
    return <em>Loading ...</em>;
  } else if (state.error) {
    return <ErrorMessage msg={"ERROR: " + state.error} />;
  } else if (state.data === "0.0.0.0") {
    return <ErrorMessage msg={"No public IP"} />;
  } else if (state.data) {
    return <em>{state.data.replace(/^::ffff:/, "")}</em>;
  } else {
    return "Loaded data is null??";
  }
}

// like loadData(), but delays the actual loading by 1sec. Allows one to
// see what the page looks like with the loading indicator
export function forTesting_loadDataWithDelay<T>(
  url: string,
  cb: DataLoadingCallback<T>,
) {
  setTimeout(() => loadData(url, cb), 1000);
}

// Do a `fetch()` call, but check the returned response and throw an error if
// the response code is not ok. Simplifies error handling
export async function fetchAndCheckResult(url: string): Promise<Response> {
  return fetch(url).then((res) => {
    if (!res.ok) {
      throw new Error(`Failed to fetch data: ${res.status} ${res.statusText}`);
    }
    return res;
  });
}
