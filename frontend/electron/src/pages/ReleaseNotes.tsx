import { Link } from "react-router-dom";

export const ReleaseNotes: React.FC = () => {
  const ul_style = {};

  const li_style = {
    margin: "5px 0",
  };

  const li_top_style = {
    listStyleType: "none",
    margin: "20px 0",
  };

  return (
    <ul style={ul_style}>
      <li style={li_top_style}>
        <b>Release 0.2.4 - Mar 26th, 2024</b>
        <ul style={ul_style}>
          <li style={li_style}>
            Fix bug that missed packets if IP addresses change. (e.g., temporary
            IPv6 address)
          </li>
          <li style={li_style}>
            Export gateway ping and uplink changes to backend.
          </li>
          <li style={li_style}>Add UUID for export to backend.</li>
          <li style={li_style}>
            Backend work to allowed client deployment by organizations.
          </li>
        </ul>
      </li>

      <li style={li_top_style}>
        <b>Release 0.2.3 - Feb 27th, 2024</b>
        <ul style={ul_style}>
          <li style={li_style}>Plot router RTT as histogram.</li>
          <li style={li_style}>Polish local network tab.</li>
          <li style={li_style}>Fix "No v4 Gateways" rendering bug.</li>
          <li style={li_style}>
            Don't assume IPv4 link-local IP to Mac mapping.
          </li>
          <li style={li_style}>
            Make "By DNS domain" the default view for flows"
          </li>
        </ul>
      </li>

      <li style={li_top_style}>
        <b>
          Release 0.2.2 - Feb 9th, 2024 -- Initial "Technical Preview Release!
        </b>
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
