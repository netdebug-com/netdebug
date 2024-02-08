import Dialog from "@mui/material/Dialog";
import { Button } from "@mui/material";

const EULA_STORAGE_KEY = "SIGNED_EULA_VERSION";
function need_to_sign_eula_version(need_version: number): boolean {
  const last_signed = localStorage.getItem(EULA_STORAGE_KEY);
  if (last_signed === null) {
    return true;
  }
  // will return NaN if not parsable
  const old_version = parseInt(last_signed, 10);
  if (Number.isNaN(old_version) || old_version < need_version) {
    return true;
  } else {
    // signed the current (or future!?) version
    // console.log("User already accepted EULA version: ", old_version);
    return false;
  }
}

function accept_eula(signed_version: number) {
  console.log("User accepted EULA version: ", signed_version);
  localStorage.setItem(EULA_STORAGE_KEY, signed_version.toString());
}

function eula_v1() {
  return (
    <div>
      <h2>
        <center>
          <b>
            NetDebug Limited Release “Technical Preview” End-User License
            Agreement
          </b>
        </center>
      </h2>
      <ol>
        <li>
          A preliminary version of the NetDebug debug software is being made
          available for a limited time basis as a “technical preview” for
          testing and evaluation of a small number of individuals. This means
          that it should not be used in production or at large scale and thus no
          warranties about the software working or not harming your computer
          systems are expressed or implied.
        </li>
        <li>
          With this license, End-Users are granted a license to use the NetDebug
          software on their personal computers at no monetary charge. Users have
          the right to make personal backups of the software but not to
          distribute to others. When the production version of NetDebug becomes
          available, users are expected to upgrade the software to the
          production version.{" "}
        </li>
        <li>
          While the final production version of NetDebug software will be made
          available under an open-source license (exact license TBD), the
          Technical Preview version will only have source code available under
          Non-Disclosure Agreement (NDA).
        </li>
        <li>
          The final version of NetDebug will employ significant personal-privacy
          preserving technologies (hashing, data mixing, obfuscation, etc.) that
          are not yet available/implemented in the Technical Preview. As a
          result, use of this software implies that
          <b>
            <em>
              {" "}
              users acknowledge that they will share with NetDebug their
              personal network performance and network “metadata”{" "}
            </em>
          </b>
          from their systems including but not limited to:
          <ol>
            <li>
              Latency, packet loss, network topology (e.g., traceroute)
              information{" "}
            </li>
            <li>
              Hosts/Websites visited (but not any packet payload/personally
              identifiable information besides public IP address){" "}
            </li>
            <li>DNS requests/responses </li>
            <li>
              Operating system statistics, log messages, and network settings
            </li>
          </ol>
        </li>
        <li>
          In return, NetDebug will take all reasonable steps to anonymize user
          data including:
          <ol>
            <li>
              Not sharing personally identifiable information with third-parties
            </li>
            <li>
              Protecting any potentially private information (e.g., public
              source IP addresses) on the back-end systems until such time as
              full privacy guards can be established (e.g., networking mixing)
            </li>
          </ol>
        </li>
        <li>
          End-users acknowledge that NetDebug’s business model is selling
          insights, data, and alerts to third-parties derived from aggregated,
          anonymized data collected in (4); the NetDebug software is only
          provided at no charge because of this business model. Users who wish
          to use the NetDebug software without participating in the data sharing
          described in (4) will be able to do so by paying a monthly
          subscription fee.
        </li>
      </ol>
    </div>
  );
}

export const EULA: React.FC = () => {
  const eula_version = 1; // BUMP me when we change the text
  // TODO: fixup styling
  if (need_to_sign_eula_version(eula_version)) {
    return (
      <center>
        <Dialog fullScreen open={true} sx={{ align: "center", width: "100%" }}>
          {eula_v1()}
          <Button
            variant={"contained"}
            onClick={() => accept_eula(eula_version)}
            sx={{ align: "center" }}
          >
            I Accept
          </Button>
        </Dialog>
      </center>
    );
  } else {
    return;
  }
};
