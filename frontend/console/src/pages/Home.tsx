import { useEffect, useState } from "react";
import { loadDataWithAuth } from "../console_utils";
import { DataLoadingState, PublicOrganizationInfo } from "../common";

export function Home() {
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
          setOrganization(resp.data.name);
        }
      },
    );
  }, []);
  return <div>Your organization is: {organization}</div>;
}

export default Home;
