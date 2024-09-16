import { generateAddresses } from "../utilAddress";

import { post, type FullDoc } from "../utilHttp";

import * as dotenv from "dotenv";
import * as dotenvExpand from "dotenv-expand";
import { JWK, type JWKObject } from "ts-jose";
const theEnv = dotenv.config();
dotenvExpand.expand(theEnv);

import { Converter } from "@iota/util.js";

const { NODE_ENDPOINT, PLUGIN_ENDPOINT, TOKEN } = process.env;

const { subtle } = globalThis.crypto;


async function run() {
    // From the menemonic a key pair
    // The account #0 will be controlling the DID
    // The account #1 will be the verification method
    // Write the key pairs to the std output
    const { bech32Addresses } = await generateAddresses(NODE_ENDPOINT, TOKEN, 1);

    // Now the JWK is generated and its public key just copied to the DID and the Private Key printed to stdout
    let key: JWK = await JWK.generate("EdDSA", {
        // At this point in time we don't know the full Kid as we don't know the DID
        // This could be done in two steps, one generating an empty DID and then adding the Ver Method through
        // an update operation
        use: "sig",
        // crv: string, some algorithms need to add curve - EdDSA
        // modulusLength: number, some algorithms need to add length - RSA
    });

    if (key === null) {
        console.log("Dummy");
    }

    const theKey = await subtle.generateKey("Ed25519", true, ["sign", "verify"]);

    const exported = await subtle.exportKey("pkcs8",
        (theKey as unknown as { [id: string]: unknown }).privateKey as CryptoKey);
    console.log("-----BEGIN PRIVATE KEY-----");
    console.log(Buffer.from(exported).toString("base64"));
    console.log("-----END PRIVATE KEY-----");

    const exported2 = await subtle.exportKey("spki",
        (theKey as unknown as { [id: string]: unknown }).publicKey as CryptoKey);
    console.log("-----BEGIN PUBLIC KEY-----");
    console.log(Buffer.from(exported2).toString("base64"));
    console.log("-----END PUBLIC KEY-----");


    // const pubKey = key.toObject(false);
    const pubKey = await subtle.exportKey("jwk",  (theKey as unknown as { [id: string]: unknown }).publicKey as CryptoKey);
    const pubKeyAsJose =  await JWK.fromObject(pubKey as JWKObject);
    const kid = await pubKeyAsJose.getThumbprint();

    // This DID Document can also be created with the help of the IOTA Identity Library
    const did = {
        id: "did:0:0",
        verificationMethod: [{
            id: `did:0:0#${kid}`,
            type: "JsonWebKey2020",
            controller: "did:0:0",
            publicKeyJwk: {}
        }]
    };

    did.verificationMethod[0].publicKeyJwk = pubKeyAsJose.toObject(false);

    // Posting data to the plugin
    const result = await postToPlugin(did, bech32Addresses);


    const privateKey = await subtle.exportKey("jwk",  (theKey as unknown as { [id: string]: unknown }).privateKey as CryptoKey);
    const privateKeyAsJose =  await JWK.fromObject(privateKey as JWKObject);
    const kidPrivate = await privateKeyAsJose.getThumbprint();

    const privateKeyObj = privateKeyAsJose.toObject(true);
    privateKeyObj.kid = `${kidPrivate}`;

    
    console.log("Private Key of the Verification Method: ");
    console.log(JSON.stringify(privateKeyObj, undefined, 2));
    console.log();

    console.log("DID: ", result.doc["id"]);
    console.log("Metadata:\n", result.meta);

    const privateKeyRaw = Buffer.from(privateKeyObj.d, "base64");
    console.log("Raw signing key: ", Converter.bytesToHex(privateKeyRaw, true));

    const publicKeyRaw = Buffer.from(pubKey.x, "base64");
    console.log("Raw public key: ", Converter.bytesToHex(publicKeyRaw, true));
}


async function postToPlugin(did: { [id: string]: unknown }, bech32Addresses: string[]): Promise<FullDoc> {
    const pluginRequest = {
        type: "DIDCreation",
        action: "Issue",
        doc: did,
        meta: {
            // The stateController address could be omitted but in that case the plugin itself will be controller
            stateControllerAddress: bech32Addresses[0]
        }
    };

    const result = await post(`${PLUGIN_ENDPOINT}/identities`, TOKEN, pluginRequest);

    return result as FullDoc;
}

export { };

run().then(() => console.log("Done")).catch(err => console.error(err));
