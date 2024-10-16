import * as dotenv from "dotenv";
import * as dotenvExpand from "dotenv-expand";

const theEnv = dotenv.config();
dotenvExpand.expand(theEnv);

import { Converter } from "@iota/util.js";


async function run() {
    const privateKeyRaw = Buffer.from("2ZwtmXOytKYXW1BvXif3U2AQoT_ECHu9OOoYMJDUY-c", "base64url");
    console.log("Raw signing key: ", Converter.bytesToHex(privateKeyRaw, true));

    const publicKeyRaw = Buffer.from("4lOGz-X9gOzLoRPX9ISxsLDfHdx-6cjsLLisDJSXiNI", "base64url");
    console.log("Raw public key: ", Converter.bytesToHex(publicKeyRaw, true));
}

export { };

run().then(() => console.log("Done")).catch(err => console.error(err));
