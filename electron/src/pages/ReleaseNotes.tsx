import { Link } from "react-router-dom";

export const ReleaseNotes: React.FC = () => {
  const ul_style = {};

  const li_style = {
    margin: "5px 0",
  };

  const li_top_style = {
    listStyleType: "none",
    margin: "10px 0",
  };

  return (
    <ul style={ul_style}>
      <b>Release 0.2.1 - Feb 9th, 2024</b>
      <li style={li_top_style}> Initial "Technical Preview Release!</li>
      <li style={li_top_style}>
        Supports:
        <ul style={ul_style}>
          <li style={li_style}>
            Per-connection <Link to={"/rtt_latency"}> latency</Link> and
            bi-directional <Link to={"/flows"}> loss information</Link>{" "}
            (aggregated by <Link to={"/flows/by_dst_domain"}>DNS domain</Link>{" "}
            and <Link to={"/flows/by_app"}>App</Link>)
          </li>
          <li style={li_style}>
            Local network <Link to={"/devices"}>device</Link>,{" "}
            <Link to={"/local_network"}> packet-loss, and latency </Link>
            monitoring
          </li>
          <li style={li_style}>
            Domain Name System resolver <Link to={"/dns"}>performance</Link>{" "}
            analysis.
          </li>
          <li style={li_style}>
            Ingress traffic testing via remote{" "}
            <Link to={"/webtest"}>web test</Link>{" "}
          </li>
          <li style={li_style}>
            Supports automated updates for MacOS and Windows (TODO: Linux
            support)
          </li>
          <li style={li_style}>
            Supports remote logging of measurements, counters, and logs
          </li>
        </ul>
      </li>
      <li style={li_top_style}>
        TODO (short-term)
        <ul style={ul_style}>
          <li style={li_style}>LOTS of simple styling/UI improvements</li>
          <li style={li_style}>Group local devices by MAC Address</li>
          <li style={li_style}>Gather local info from mDNS/Bonjour</li>
        </ul>
      </li>
      <li style={li_top_style}>
        TODO (long-term):
        <ul style={ul_style}>
          <li style={li_style}>
            {" "}
            Google Maps-esque view of geo-located routers
          </li>
          <li style={li_style}>
            {" "}
            Implement strong privacy guarantees, e.g., OnionRouting style mixes{" "}
          </li>
          <li style={li_style}>
            Figure out Open-Source logistics (license, separating desktop from
            server, etc.)
          </li>
          <li style={li_style}> TODO: fill in more TODOs</li>
          <li style={li_style}> Lots of polish </li>
        </ul>
      </li>
    </ul>
  );
};
