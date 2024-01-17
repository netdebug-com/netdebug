import React from "react";
import { desktop_api_url } from "../utils";
import { useLoaderData } from "react-router";

// FIXME: need to use a different pattern to load the data.
// (a) this request needs to go to the topology server so it could take a while
//     (react-router / useDataLoader has "Loading..." indicators. Need to investigate
// (b) we want to call multiple different APIs to populate the homepage ==> find best way
//     to do that.
export const myIpLoader = async () => {
  const res = await fetch(desktop_api_url("get_my_ip"));
  return res.json();
};

const Home: React.FC = () => {
  const myIp = useLoaderData() as string;

  return (
    <div>
      <h1>Home Page</h1>
      My external IP Address is <em>{myIp}</em>.
    </div>
  );
};

export default Home;
