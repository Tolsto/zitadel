import { createClientFor } from "@zitadel/client";
import { IdentityProviderService } from "@zitadel/proto/zitadel/idp/v2/idp_service_pb";
import { OIDCService } from "@zitadel/proto/zitadel/oidc/v2/oidc_service_pb";
import { OrganizationService } from "@zitadel/proto/zitadel/org/v2/org_service_pb";
import { SAMLService } from "@zitadel/proto/zitadel/saml/v2/saml_service_pb";
import { SessionService } from "@zitadel/proto/zitadel/session/v2/session_service_pb";
import { SettingsService } from "@zitadel/proto/zitadel/settings/v2/settings_service_pb";
import { UserService } from "@zitadel/proto/zitadel/user/v2/user_service_pb";
import { systemAPIToken, machineUserToken } from "./api";
import { createServerTransport } from "./zitadel";

let cachedMachineToken: string | undefined;
let tokenPromise: Promise<string> | null = null;

const isMachineKeyAuth = process.env.AUDIENCE &&
    process.env.MACHINE_USER_ID &&
    process.env.MACHINE_USER_KEY_ID &&
    process.env.MACHINE_USER_PRIVATE_KEY

type ServiceClass =
  | typeof IdentityProviderService
  | typeof UserService
  | typeof OrganizationService
  | typeof SessionService
  | typeof OIDCService
  | typeof SettingsService
  | typeof SAMLService;

// Helper function to ensure that only one request
// obtains the access token at a time
async function getMachineToken(): Promise<string> {
  if (!tokenPromise) {
    tokenPromise = machineUserToken({
      privateKeyB64: process.env.MACHINE_USER_PRIVATE_KEY!,
      machineUserId: process.env.MACHINE_USER_ID!,
      machineUserKeyId: process.env.MACHINE_USER_KEY_ID!,
      audience: process.env.AUDIENCE!,
    })
      .then((token) => {
        cachedMachineToken = token;
        tokenPromise = null;
        return token;
      })
      .catch((err) => {
        tokenPromise = null;
        throw err;
      });
  }
  return tokenPromise;
}

export async function createServiceForHost<T extends ServiceClass>(
  service: T,
  serviceUrl: string,
) {
  let token;

  // if we are running in a multitenancy context, use the system user token
  if (
    process.env.AUDIENCE &&
    process.env.SYSTEM_USER_ID &&
    process.env.SYSTEM_USER_PRIVATE_KEY
  ) {
    token = await systemAPIToken();
  } else if (isMachineKeyAuth) {
    if (!cachedMachineToken) {
      token = await getMachineToken();
    } else {
      token = cachedMachineToken;
    }
  } else if (process.env.ZITADEL_SERVICE_USER_TOKEN) {
    token = process.env.ZITADEL_SERVICE_USER_TOKEN;
  }

  if (!serviceUrl) {
    throw new Error("No instance url found");
  }

  if (!token) {
    throw new Error("No token found");
  }

  let internalClient = createClientFor<T>(service)(
    createServerTransport(token, serviceUrl),
  );

  // Create a proxy around the client to intercept all method calls
  return new Proxy(internalClient, {
    get(target, propKey, receiver) {
      // Re-bind the method to the most current client instance
      const origMethod = internalClient[propKey as keyof typeof internalClient];

      if (typeof origMethod === "function") {
        return async function (...args: any[]) {
          try {
            // @ts-ignore
            return await origMethod.apply(internalClient, args);
          } catch (error: any) {
            // simplistic check for token expiration, only for machine users
            // with key auth
            if (isMachineKeyAuth && error.code === 16) {
              // Invalidate the cached token
              cachedMachineToken = undefined;

              const newToken = await getMachineToken();

              // Create a new transport and client with the new token
              const newTransport = createServerTransport(newToken, serviceUrl);
              internalClient = createClientFor<T>(service)(newTransport);

              // Retry the original method with the new client
              const newOrigMethod =
                internalClient[propKey as keyof typeof internalClient];
              // @ts-ignore
              return await newOrigMethod.apply(internalClient, args);
            }
            // Re-throw other errors
            throw error;
          }
        };
      }
      return Reflect.get(target, propKey, receiver);
    },
  });
}
