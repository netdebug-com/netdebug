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
      <b>Release 0.2.3 - Feb 27th, 2024</b>
      <li style={li_top_style}> Initial "Technical Preview Release!</li>
      <li style={li_top_style}>
        Many bugfixes and UI improvements:
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
