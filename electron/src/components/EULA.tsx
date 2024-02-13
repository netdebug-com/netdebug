import Dialog from "@mui/material/Dialog";
import { Button } from "@mui/material";

// HACK: if a user has accepted the v2 EULA with the previous flow
// (browser local storage), lets accept it right back.
const EULA_STORAGE_KEY = "SIGNED_EULA_VERSION";
function eulaSignedWithLocalStorage() {
  const last_signed = localStorage.getItem(EULA_STORAGE_KEY);
  if (last_signed === null) {
    return false;
  }
  // will return NaN if not parsable
  const old_version = parseInt(last_signed, 10);
  if (Number.isNaN(old_version) || old_version < 2) {
    return false;
  } else {
    console.log("User previously already accepted EULA version: ", old_version);
    return true;
  }
}

function eula_v2() {
  // manually included from resources/EULA.html and editted
  return (
    <div>
      <h2>
        <b>
          NetDebug Limited Release “Technical Preview” End-User License
          Agreement
        </b>
      </h2>
      <ul>
        <li>
          {" "}
          <em>Limited "BETA" Release</em>. While the final production version of
          NetDebug Software will be made available under an open-source license
          (exact license TBD), this Technical Preview version will be available
          only under this more restricted proprietary license. Source code can
          separately be made available for review under Non-Disclosure Agreement
          (NDA).
        </li>
        <li>
          {" "}
          <em>User Data Privacy</em>. The final version of NetDebug will employ
          significant personal-privacy preserving technologies (hashing, data
          mixing, obfuscation, etc.) that are not yet available/implemented in
          the Technical Preview. As a result, use of this software implies that
          the{" "}
          <b>
            users acknowledge that they will share with NetDebug their personal
            network performance and network “metadata”{" "}
          </b>{" "}
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
              Operating system statistics, log messages, and network settings{" "}
            </li>
          </ol>
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
          End-Users acknowledge that NetDebug’s business model is selling
          insights, data, and alerts to third-parties derived from aggregated,
          anonymized data collected from end-users; the NetDebug software is
          only provided at no charge because of this business model. Users who
          wish to use the NetDebug software without participating in the data
          sharing described in this section will be able to do so by paying a
          monthly subscription fee.
        </li>
        <li>
          {" "}
          <em>Access Restrictions</em>. End-User will not at any time and will
          not permit any third party to, directly or indirectly: (i) use the
          NetDebug software in any manner beyond the scope of rights expressly
          granted in this Agreement; (ii) modify or create derivative works of
          the NetDebug software, in whole or in part; (iii) reverse engineer,
          disassemble, decompile, decode or otherwise attempt to derive or gain
          improper access to any software component of the NetDebug software, in
          whole or in part; (iv) frame, mirror, sell, resell, rent or lease use
          of the NetDebug software to any third party, or otherwise allow any
          third party to use the NetDebug software for any purpose other than
          for the benefit of End-User in accordance with this Agreement; (v) use
          the NetDebug software in any manner or for any purpose that infringes,
          misappropriates, or otherwise violates any intellectual property right
          or other right of any third party, or that violates any applicable
          law; (vi) interfere with, or disrupt the integrity or performance of,
          the NetDebug software, or any data or content contained therein or
          transmitted thereby; (vii) access or search the NetDebug software (or
          download any data or content contained therein or transmitted thereby)
          through the use of any engine, software, tool, agent, device or
          mechanism (including spiders, robots, crawlers or any other similar
          data mining tools) other than software or NetDebug software features
          provided by NetDebug for use expressly for such purposes; or (viii)
          use the NetDebug software or any other NetDebug confidential
          information for benchmarking or competitive analysis with respect to
          competitive or related products or NetDebug software, or to develop,
          commercialize, license or sell any product, service or technology that
          could, directly or indirectly, compete with the NetDebug software.
        </li>
        <li>
          {" "}
          <em>Reservation of Rights</em>. NetDebug will own and retain all
          right, title and interest in and to the NetDebug software, the
          underlying tools, know-how, methodologies, algorithms, models and
          proprietary information used to provide or power the NetDebug
          software, any aggregate, derivative or usage data collected or
          generated in connection with the NetDebug software in de-identified
          form, all improvements, derivatives, enhancements and modifications to
          any of the foregoing, and all intellectual property rights therein
          (collectively, “NetDebug Materials”). All rights not expressly granted
          hereunder are hereby reserved. Feedback. From time to time End-User or
          its employees, contractors, or representatives may provide NetDebug
          with suggestions, comments, feedback or the like with regard to the
          NetDebug software (collectively, “Feedback”). End-User hereby grants
          NetDebug a perpetual, irrevocable, royalty-free and fully-paid-up
          license to use and exploit all Feedback in connection with NetDebug’s
          business purposes, including, without limitation, the testing,
          development, maintenance and improvement of the NetDebug software.
        </li>
        <li>
          {" "}
          <em>Termination</em>. In the event of any termination or expiration of
          this Agreement, all rights and licenses granted hereunder will
          immediately cease, but the following provisions will survive any
          termination or expiration of this Agreement: Sections 2, 4, and 5.
        </li>
        <li>
          {" "}
          <em>DISCLAIMER</em>. THE NETDEBUG SOFTWARE, NETDEBUG MATERIALS AND
          ANYTHING ELSE PROVIDED BY NETDEBUG, ITS VENDORS AND LICENSORS, AS
          APPLICABLE, IN CONNECTION WITH THIS AGREEMENT ARE PROVIDED ON AN “AS
          IS” BASIS AND NETDEBUG MAKES NO WARRANTIES OF ANY KIND, EXPRESS,
          IMPLIED, STATUTORY OR OTHERWISE, INCLUDING WITHOUT LIMITATION
          WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, AND
          NONINFRINGEMENT, THAT THE NETDEBUG SOFTWARE OR NETDEBUG MATERIAL ARE
          FREE FROM DEFECTS, ERRORS, INACCURACIES OR BUGS. LIMITATION OF
          LIABILITY. IN NO EVENT WILL NETDEBUG BE LIABLE FOR ANY SPECIAL,
          INCIDENTAL, PUNITIVE OR CONSEQUENTIAL DAMAGES, LOST PROFITS OR
          REVENUE, LOSS OF USE, LOST BUSINESS OPPORTUNITIES OR LOSS OF GOODWILL,
          OR COST OF REPLACEMENT PRODUCTS OR NETDEBUG SOFTWARE, ARISING OUT OF,
          RELATING TO OR IN CONNECTION WITH THIS AGREEMENT OR ANY NETDEBUG
          SOFTWARE, NETDEBUG MATERIALS, OR ANY ANYTHING ELSE PROVIDED BY
          NETDEBUG HEREUNDER, WHETHER SUCH LIABILITY ARISES FROM ANY CLAIM BASED
          UPON CONTRACT, WARRANTY, INTELLECTUAL PROPERTY, TORT (INCLUDING
          WITHOUT LIMITATION NEGLIGENCE), PRODUCT LIABILITY OR OTHERWISE,
          WHETHER OR NOT NETDEBUG HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH
          LOSS OR DAMAGE. IN NO EVENT WILL NETDEBUG’S AGGREGATE LIABILITY UNDER
          THIS AGREEMENT, WHETHER BY CONTRACT, TORT (INCLUDING, WITHOUT
          LIMITATION, NEGLIGENCE) OR OTHERWISE, EXCEED $10,000.00. THE FOREGOING
          LIMITATIONS WILL APPLY EVEN IF ANY STATED REMEDY HEREUNDER FAILS OF
          ITS ESSENTIAL PURPOSE.
        </li>
        <li>
          {" "}
          <em>Governing Law; Jurisdiction</em>. This Agreement will be governed
          by and construed in accordance with the laws of the State of
          California without giving effect to any principles of conflict of laws
          that would lead to the application of the laws of another
          jurisdiction. Any legal action or proceeding arising under this
          Agreement will be brought exclusively in the federal or state courts
          located in the Northern District of California and the parties
          irrevocably consent to the personal jurisdiction and venue therein.
        </li>
      </ul>
    </div>
  );
}

export const EULA: React.FC = () => {
  // TODO: fixup styling
  if (eulaSignedWithLocalStorage()) {
    window.netdebugApi.eulaAccepted();
  }
  return (
    <center>
      <Dialog fullScreen open={true} sx={{ align: "center", width: "100%" }}>
        {eula_v2()}
        <Button
          variant={"contained"}
          onClick={() => window.netdebugApi.eulaAccepted()}
          sx={{ align: "center" }}
        >
          I Accept
        </Button>
      </Dialog>
    </center>
  );
};
