import { lazy } from "react";
import type { Path } from "react-router-dom";
import type { AccessType } from "@iamshield/iamshield-admin-client/lib/defs/whoAmIRepresentation";
import { generateEncodedPath } from "../../utils/generateEncodedPath";
import type { AppRouteObject } from "../../routes";

export type PermissionsConfigurationTabs =
  | "permissions"
  | "policies"
  | "evaluation";

export type PermissionsConfigurationTabsParams = {
  realm: string;
  permissionClientId: string;
  tab: PermissionsConfigurationTabs;
};

const PermissionsConfigurationSection = lazy(
  () => import("../PermissionsConfigurationSection"),
);

export const PermissionsConfigurationTabsRoute: AppRouteObject = {
  path: "/:realm/permissions/:permissionClientId/:tab",
  element: <PermissionsConfigurationSection />,
  handle: {
    access: (accessChecker: { hasAny: (...types: AccessType[]) => boolean }) =>
      accessChecker.hasAny("view-realm", "view-clients", "view-users"),
  },
};

export const toPermissionsConfigurationTabs = (
  params: PermissionsConfigurationTabsParams,
): Partial<Path> => ({
  pathname: generateEncodedPath(PermissionsConfigurationTabsRoute.path, params),
});



