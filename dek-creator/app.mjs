import { ClientEncryption } from "mongodb-client-encryption";
import { fromNodeProviderChain } from "@aws-sdk/credential-providers"; // ES6 import
import mongodb from "mongodb";
import fs from "fs";
import { v4 as stringify } from "uuid";
import {
  SecretsManagerClient,
  GetSecretValueCommand,
} from '@aws-sdk/client-secrets-manager';

const { MongoClient } = mongodb;

const KEY_NAMESPACE = `encryption.__keyVault`;

/**
 * Retrieves secret data from AWS Secrets Manager.
 *
 * @param {string} secretId The identifier for the secret in AWS Secrets Manager.
 * @param {string} region The AWS region where the Secrets Manager is hosted.
 * @returns {Promise<Object>} A promise that resolves with the secret data as a JSON object.
 */
const getSecretManagerData = async () => {
  const secretsManagerClient = new SecretsManagerClient({ region: "ap-south-1" });
  const secretsCommand = new GetSecretValueCommand({ SecretId: "staging-platform-pii-lambda" });
  const secretsResponse = await secretsManagerClient.send(secretsCommand);
  return JSON.parse(secretsResponse.SecretString);
};

/**
 * Initializes MongoDB connection and sets the dbInstance.
 * @returns {Promise<MongoClient>}
 */
const initializeMongodb = async (uri) => {
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
const initialize = async (dbClient) => {
  const provider = fromNodeProviderChain();
  const aws = await provider();
  const encryptionInstance = new ClientEncryption(dbClient, {
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
    const secrets = await getSecretManagerData();
    if (!kmsKeyArn || !kmsKeyRegion || !dekAltName) {
      throw new Error(
        `One of the parameter is not provided kmsKeyArn: ${kmsKeyArn}, kmsKeyRegion: ${kmsKeyRegion}, dekAltName: ${dekAltName}`
      );
    }
    const dbClient = await initializeMongodb(secrets.MONGODB_URI);
    const encryptionInstance = await initialize(dbClient);
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
