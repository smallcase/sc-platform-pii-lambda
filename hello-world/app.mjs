import { ClientEncryption } from "mongodb-client-encryption";
import { fromNodeProviderChain } from "@aws-sdk/credential-providers"; // ES6 import
import mongodb from "mongodb";
import fs from "fs";
import { v4 as stringify } from "uuid";

const { MongoClient } = mongodb;

const KEY_NAMESPACE = `encryption.__keyVault`;

let encryptionInstance = null;

const uri = process.env.MONGODB_URI;
let dbClient = null;

/**
 * Initializes MongoDB connection and sets the dbInstance.
 * @returns {Promise<MongoClient>}
 */
const initializeMongodb = async () => {
  try {
    const client = new MongoClient(uri, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });
    await client.connect();
    return client;
  } catch (err) {
    throw err;
  }
};

/**
 *
 * @returns { Promise<ClientEncryption> }
 */
const initialize = async () => {
  const provider = fromNodeProviderChain();
  const aws = await provider();
  encryptionInstance = new ClientEncryption(dbClient, {
    keyVaultNamespace: KEY_NAMESPACE,
    kmsProviders: {
      aws: {
        accessKeyId: aws.accessKeyId,
        secretAccessKey: aws.secretAccessKey,
        sessionToken: aws.sessionToken,
      },
    },
  });
  return encryptionInstance;
};

/**
 *
 * Event doc: https://docs.aws.amazon.com/apigateway/latest/developerguide/set-up-lambda-proxy-integrations.html#api-gateway-simple-proxy-for-lambda-input-format
 * @param {Object} event - API Gateway Lambda Proxy Input Format
 *
 * Context doc: https://docs.aws.amazon.com/lambda/latest/dg/nodejs-prog-model-context.html
 * @param {Object} context
 *
 * Return doc: https://docs.aws.amazon.com/apigateway/latest/developerguide/set-up-lambda-proxy-integrations.html
 * @returns {Object} object - API Gateway Lambda Proxy Output Format
 *
 */

export const lambdaHandler = async (event, context) => {
  try {
    const { kmsKeyArn, kmsKeyRegion, dekAltName } = event;
    if (!kmsKeyArn || !kmsKeyRegion || !dekAltName) {
      throw new Error(
        `One of the parameter is not provided kmsKeyArn: ${kmsKeyArn}, kmsKeyRegion: ${kmsKeyRegion}, dekAltName: ${dekAltName}`
      );
    }
    await initializeMongodb();
    await initialize();
    const masterKey = {
      key: kmsKeyArn,
      region: kmsKeyRegion,
    };
    const dataKey = await encryptionInstance.createDataKey("aws", {
      masterKey: masterKey,
      keyAltNames: [dekAltName],
    });
    const uuidString = stringify(dataKey.buffer);
    console.log(uuidString)
    return {
      statusCode: 200,
      body: JSON.stringify({
        dataKeyUUID: uuidString,
      }),
    };
  } catch (err) {
    console.log(err)
    return {
      statusCode: 200,
      body: JSON.stringify({
        message: "error",
        error: JSON.stringify(err)
      }),
    };
  }
};

if (process.env.ENV === "local") {
  const eventsStringified = fs.readFileSync("./event.json", "utf8");
  const events = JSON.parse(eventsStringified);
  lambdaHandler(events);
}
