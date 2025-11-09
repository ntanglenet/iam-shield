import KeycloakAdminClient from "@iamshield/iamshield-admin-client";
import {
  createNamedContext,
  useRequiredContext,
} from "@iamshield/iamshield-ui-shared";
import type Keycloak from "keycloak-js";
import type { Environment } from "./environment";

export type AdminClientProps = {
  iamshield: Keycloak;
  adminClient: KeycloakAdminClient;
};

export const AdminClientContext = createNamedContext<
  AdminClientProps | undefined
>("AdminClientContext", undefined);

export const useAdminClient = () => useRequiredContext(AdminClientContext);

export async function initAdminClient(
  iamshield: Keycloak,
  environment: Environment,
) {
  const adminClient = new KeycloakAdminClient();

  adminClient.setConfig({ realmName: environment.realm });
  adminClient.baseUrl = environment.adminBaseUrl;
  adminClient.registerTokenProvider({
    async getAccessToken() {
      try {
        await iamshield.updateToken(5);
      } catch {
        await iamshield.login();
      }

      return iamshield.token;
    },
  });

  return adminClient;
}
