import type { ServerInfoRepresentation } from "@iamshield/iamshield-admin-client/lib/defs/serverInfoRepesentation";
import {
  createNamedContext,
  IamshieldSpinner,
  useFetch,
  useRequiredContext,
} from "@iamshield/iamshield-ui-shared";
import { PropsWithChildren, useState } from "react";
import { useAdminClient } from "../../admin-client";
import { sortProviders } from "../../util";

export const ServerInfoContext = createNamedContext<
  ServerInfoRepresentation | undefined
>("ServerInfoContext", undefined);

export const useServerInfo = () => useRequiredContext(ServerInfoContext);

export const useLoginProviders = () =>
  sortProviders(useServerInfo().providers!["login-protocol"].providers);

export const ServerInfoProvider = ({ children }: PropsWithChildren) => {
  const { adminClient } = useAdminClient();
  const [serverInfo, setServerInfo] = useState<ServerInfoRepresentation>();

  useFetch(() => adminClient.serverInfo.find(), setServerInfo, []);

  if (!serverInfo) {
    return <IamshieldSpinner />;
  }

  return (
    <ServerInfoContext.Provider value={serverInfo}>
      {children}
    </ServerInfoContext.Provider>
  );
};
