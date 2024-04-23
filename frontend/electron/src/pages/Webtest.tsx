import {
  FormControl,
  InputLabel,
  MenuItem,
  Select,
  SelectChangeEvent,
} from "@mui/material";
import { useState } from "react";

function getVantageUrl(vantagePoint: string) {
  const urlSuffix = "topology.netdebug.com/webtest_8338550042";
  switch (vantagePoint) {
    case "sea1":
    case "bay1":
    case "nyc1":
      return `https://${vantagePoint}.${urlSuffix}`;
    case "dal1":
      // the cert for dal1.topology.netdebug.com is currently busted. It's CN is
      // just `topology.netdebug.com`. So we need to return that as URL otherwise
      // we get SSL errors.
      return `https://${urlSuffix}`;
    default:
      return null;
  }
}

export default function Webtest() {
  const [vantage, setVantage] = useState("");

  const url = getVantageUrl(vantage);
  console.log("Using vantage point:", url ? url : "None");
  return (
    <>
      <div style={{ display: "flex", alignItems: "center" }}>
        <FormControl sx={{ width: "300px" }}>
          <InputLabel id="webtest-vantage-selection-label">
            Server Location
          </InputLabel>
          <Select
            id="webtest-vantage-selection"
            labelId="webtest-vantage-selection-label"
            value={vantage}
            onChange={(ev: SelectChangeEvent) => setVantage(ev.target.value)}
            label="Server Location"
            fullWidth
          >
            <MenuItem value="sea1">Seattle</MenuItem>
            <MenuItem value="bay1">SF Bay Area</MenuItem>
            <MenuItem value="dal1">Texas</MenuItem>
            <MenuItem value="nyc1">New York</MenuItem>
          </Select>
        </FormControl>
      </div>
      {
        // The webtest page uses a fixed height as far as I can tell. So lets
        // hardcode this here, otherwise the iframe looks ugly with scroll bars and
        // all...
        // TODO: replace this iframe with a native UI and talk to the webserver
        // over RPC (via the desktop probably)
      }
      {url && <iframe src={url} style={{ width: "100%", height: "950px" }} />}
      {!url && (
        <div style={{ padding: "30px" }}>
          Select a server location to start the test
        </div>
      )}
    </>
  );
}
