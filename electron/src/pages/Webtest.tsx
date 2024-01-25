export default function Webtest() {
  return (
    // The webtest page uses a fixed height as far as I can tell. So lets
    // hardcode this here, otherwise the iframe looks ugly with scroll bars and
    // all...
    // TODO: replace this iframe with a native UI and talk to the webserver
    // over RPC (via the desktop probably)
    <iframe
      src="https://topology.netdebug.com/webtest_8338550042"
      style={{ width: "100%", height: "950px" }}
    />
  );
}
