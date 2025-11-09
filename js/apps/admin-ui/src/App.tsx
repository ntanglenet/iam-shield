import KeycloakAdminClient from "@iamshield/iamshield-admin-client";
import {
  mainPageContentId,
  useEnvironment,
} from "@iamshield/iamshield-ui-shared";
import { Flex, FlexItem, Page } from "@patternfly/react-core";
import { PropsWithChildren, Suspense, useEffect, useState } from "react";
import { Outlet } from "react-router-dom";

import {
  ErrorBoundaryFallback,
  ErrorBoundaryProvider,
  IamshieldSpinner,
} from "@iamshield/iamshield-ui-shared";
import { Header } from "./PageHeader";
import { PageNav } from "./PageNav";
import { AdminClientContext, initAdminClient } from "./admin-client";
import { PageBreadCrumbs } from "./components/bread-crumb/PageBreadCrumbs";
import { ErrorRenderer } from "./components/error/ErrorRenderer";
import { RecentRealmsProvider } from "./context/RecentRealms";
import { AccessContextProvider } from "./context/access/Access";
import { RealmContextProvider } from "./context/realm-context/RealmContext";
import { ServerInfoProvider } from "./context/server-info/ServerInfoProvider";
import { WhoAmIContextProvider } from "./context/whoami/WhoAmI";
import type { Environment } from "./environment";
import { SubGroups } from "./groups/SubGroupsContext";
import { AuthWall } from "./root/AuthWall";
import { Banners } from "./Banners";

export const AppContexts = ({ children }: PropsWithChildren) => (
  <ErrorBoundaryProvider>
    <ErrorBoundaryFallback fallback={ErrorRenderer}>
      <ServerInfoProvider>
        <RealmContextProvider>
          <WhoAmIContextProvider>
            <RecentRealmsProvider>
              <AccessContextProvider>
                <SubGroups>{children}</SubGroups>
              </AccessContextProvider>
            </RecentRealmsProvider>
          </WhoAmIContextProvider>
        </RealmContextProvider>
      </ServerInfoProvider>
    </ErrorBoundaryFallback>
  </ErrorBoundaryProvider>
);

export const App = () => {
  const { Iamshield, environment } = useEnvironment<Environment>();
  const [adminClient, setAdminClient] = useState<KeycloakAdminClient>();

  useEffect(() => {
    const init = async () => {
      const client = await initAdminClient(Iamshield, environment);
      setAdminClient(client);
    };
    init().catch(console.error);
  }, []);

  if (!adminClient) return <IamshieldSpinner />;
  return (
    <AdminClientContext.Provider value={{ iamshield: Iamshield, adminClient }}>
      <AppContexts>
        <Flex
          direction={{ default: "column" }}
          flexWrap={{ default: "nowrap" }}
          spaceItems={{ default: "spaceItemsNone" }}
          style={{ height: "100%" }}
        >
          <FlexItem>
            <Banners />
          </FlexItem>
          <FlexItem grow={{ default: "grow" }} style={{ minHeight: 0 }}>
            <Page
              header={<Header />}
              isManagedSidebar
              sidebar={<PageNav />}
              breadcrumb={<PageBreadCrumbs />}
              mainContainerId={mainPageContentId}
            >
              <ErrorBoundaryFallback fallback={ErrorRenderer}>
                <Suspense fallback={<IamshieldSpinner />}>
                  <AuthWall>
                    <Outlet />
                  </AuthWall>
                </Suspense>
              </ErrorBoundaryFallback>
            </Page>
          </FlexItem>
        </Flex>
      </AppContexts>
    </AdminClientContext.Provider>
  );
};
