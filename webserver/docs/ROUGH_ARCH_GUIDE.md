# Context and Caveats

The backend server (born the `webserver` but now has many more functions) should have some common design elements.
This doc tries to enumerate them and explain why these choices were made.

Three main components: the webserver, the GUI, and the backend SQL database.


1. All business logic is in RUST; presentation logic in javascript.
    This allows better type checking and control (and testing!) of critical functions (e.g., list all of the flows)
2. The webserver and GUI only contain soft state; only the backened SQL db has hard state.
    This simplifies the high-availability model and allows people to roughly seemlessly fail over from
    one instance of the GUI/webserver to another (perhaps at the cost of being forced to reload/logback in).
3. Communication between the GUI and webserver should be largely by REST using JSON Webtokens (JWT - https://jwt.io/introduction ) issued by the webserver as auth token/user identifiers.  Websockets aren't really that easy to do 
in React and many of the GUI <--> webserver interactions will need to be public APIs at some point.
4. Our customers will probably demand an "API-first" architecture where everything they see through the GUI is 
    available through some API call.  We need to keep that in mind as we design our communications.
5. We can translate JWT's issued by other identity providers to own internal providers using a REST call, e.g., /post/auth; and most call to the webserver will require a JWT signed authtoken from us. FYI: https://github.com/Keats/jsonwebtoken
6.  This lets us encode all sorts of useful state into our custom JWT (admin rights, company domain, etc.) and simplies
    the REST handlers and thus the GUI rendering.
7. All data structures that are shared between components (e.g., webserver and GUI) have their source-of-truth in RUST and are exported to typescript via the `typescript_type_def::TypeDef` macro.  Dates should (generally) be exported as strings, as should IP addresses.  TODO: add other hard-to-translate types here.



# Adding A New device workflow

1. A device's admin installs NetDebug on the device
2. On startup, NetDebug generates a pub key pair and unique ID
3. The device reads a 'company' config from a config file in a well-known location including the company's pub key signed by netdebug
4. When the device's netdebug agent connects to the topology server, it stays in a 'pending' state until the company
    admin approves it.

NOTE: we could have the admins instead generate a per-device signed key, but I think distributing a unique file to each device will be too much work.  I think clicking through (likely in bulk) through the admin console to approve devices is likely easier.  Yes, there's a chance that someone could steal the company pub key and try to get their device added to the list of devices in the company's view, but that seems of dubious value except perhaps DoS.

