import * as dotenv from "dotenv";
import * as dotenvExpand from "dotenv-expand";
import { JWK, type JWKObject } from "ts-jose";
const theEnv = dotenv.config();
dotenvExpand.expand(theEnv);

import { Converter } from "@iota/util.js";

const { subtle } = globalThis.crypto;


async function run() {
    const pemUrl = process.argv[2];

    const theKey = await subtle.generateKey("Ed25519", true, ["sign", "verify"]);
    const privateKey = (theKey as unknown as { [id: string]: unknown }).privateKey as CryptoKey;
    const publicKey = (theKey as unknown as { [id: string]: unknown }).publicKey as CryptoKey;

    // const pubKey = key.toObject(false);
    const pubKey = await subtle.exportKey("jwk", publicKey);
    const pubKeyAsJose = await JWK.fromObject(pubKey as JWKObject);
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

    const pubKeyObj = pubKeyAsJose.toObject(false);
    if (pemUrl) {
        pubKeyObj.x5u = pemUrl;
    }
    pubKeyObj.use = "sig";
    pubKeyObj.alg = "EdDSA";
    pubKeyObj.kid = await pubKeyAsJose.getThumbprint();

    did.verificationMethod[0].publicKeyJwk = pubKeyObj;
    // delete did.verificationMethod[0].publicKeyJwk["key_ops"];

    const privateKeyAsJsonWebKey = await subtle.exportKey("jwk", privateKey);
    const privateKeyAsJose = await JWK.fromObject(privateKeyAsJsonWebKey as JWKObject);
    const kidPrivate = await privateKeyAsJose.getThumbprint();

    const privateKeyObj = privateKeyAsJose.toObject(true);
    privateKeyObj.kid = kidPrivate;
    privateKeyObj.alg = "EdDSA";
    privateKeyObj.use = "sig";

    const privateKeyRaw = Buffer.from(privateKeyObj.d, "base64");
    const publicKeyRaw = Buffer.from(pubKey.x, "base64");

    const finalObject = {
        "publicKeyJwk": pubKeyObj,
        "privateKeyJwk": privateKeyObj,
        "privateKeyVerificationMethodRaw": Converter.bytesToHex(privateKeyRaw, true),
        "publicKeyVerificationMethodRaw": Converter.bytesToHex(publicKeyRaw, true)
    };

    console.log(JSON.stringify(finalObject, undefined, 2));

    const exported = await subtle.exportKey("pkcs8", privateKey);
    console.log("-----BEGIN PRIVATE KEY-----");
    console.log(Buffer.from(exported).toString("base64"));
    console.log("-----END PRIVATE KEY-----");

    const exported2 = await subtle.exportKey("spki", publicKey);
    console.log("-----BEGIN PUBLIC KEY-----");
    console.log(Buffer.from(exported2).toString("base64"));
    console.log("-----END PUBLIC KEY-----");
}


export { };

run().then(() => console.log("Done")).catch(err => console.error(err));
