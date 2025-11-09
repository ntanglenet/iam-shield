import { AuthenticationProviderRepresentation } from "@iamshield/iamshield-admin-client/lib/defs/authenticatorConfigRepresentation";
import {
  createNamedContext,
  useFetch,
  useRequiredContext,
} from "@iamshield/iamshield-ui-shared";
import { PropsWithChildren, useState } from "react";
import { useAdminClient } from "../../admin-client";

export const AuthenticationProviderContext = createNamedContext<
  { providers?: AuthenticationProviderRepresentation[] } | undefined
>("AuthenticationProviderContext", undefined);

export const AuthenticationProviderContextProvider = ({
  children,
}: PropsWithChildren) => {
  const { adminClient } = useAdminClient();
  const [providers, setProviders] =
    useState<AuthenticationProviderRepresentation[]>();

  useFetch<AuthenticationProviderRepresentation[][]>(
    async () =>
      Promise.all([
        adminClient.authenticationManagement.getClientAuthenticatorProviders(),
        adminClient.authenticationManagement.getFormActionProviders(),
        adminClient.authenticationManagement.getAuthenticatorProviders(),
      ]),
    (providers) => setProviders(providers.flat() as AuthenticationProviderRepresentation[]),
    [],
  );

  return (
    <AuthenticationProviderContext.Provider value={{ providers }}>
      {children}
    </AuthenticationProviderContext.Provider>
  );
};

export const useAuthenticationProvider = () =>
  useRequiredContext(AuthenticationProviderContext);
