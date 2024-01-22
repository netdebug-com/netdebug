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

// like loadData(), but delays the actual loading by 1sec. Allows one to
// see what the page looks like with the loading indicator
export function forTesting_loadDataWithDelay<T>(
  url: string,
  cb: DataLoadingCallback<T>,
) {
  setTimeout(() => loadData(url, cb), 1000);
}
