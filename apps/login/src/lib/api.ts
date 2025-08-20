import { newSystemToken } from "@zitadel/client/node";
import { ServiceAccount } from "@zitadel/node/dist/credentials/service-account";

export async function systemAPIToken() {
  const token = {
    audience: process.env.AUDIENCE,
    userID: process.env.SYSTEM_USER_ID,
    token: Buffer.from(process.env.SYSTEM_USER_PRIVATE_KEY, "base64").toString(
      "utf-8",
    ),
  };

  return newSystemToken({
    audience: token.audience,
    subject: token.userID,
    key: token.token,
  });
}

export async function machineUserToken(tokenOptions: {
  privateKeyB64: string,
  machineUserId: string,
  machineUserKeyId: string,
  audience: string}
): Promise<string> {
  const key = Buffer.from(tokenOptions.privateKeyB64, "base64").toString("utf-8")

  const serviceAccount = new ServiceAccount(
    tokenOptions.machineUserId,
    tokenOptions.machineUserKeyId,
    key
  );

  return await serviceAccount.authenticate(tokenOptions.audience, {apiAccess: true});
}