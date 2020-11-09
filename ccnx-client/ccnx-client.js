var ffi = require("ffi-napi");

var libccnxClient = ffi.Library("./libccnx_client", {
  ccnxClient: ["int", ["string", "string", "string"]],
});

if (process.argv.length < 2) {
  console.log(
    "Arguments: " + process.argv[0] + " " + process.argv[1] + " <max>"
  );
  process.exit();
}

const keyfile =
  "/home/otocn/CCNx_Distillery/key-store/keystoreserver.otocn";
const keypassword = "123321";
const ccnxName = "lci:/ccn-name/4";

var output = libccnxClient.ccnxClient(keyfile, keypassword, ccnxName);

console.log("Your output: " + output);
