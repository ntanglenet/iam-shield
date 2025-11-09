import { lazy } from "react";
import type { Path } from "react-router-dom";
import type { AccessType } from "@iamshield/iamshield-admin-client/lib/defs/whoAmIRepresentation";
import { generateEncodedPath } from "../../utils/generateEncodedPath";
import type { AppRouteObject } from "../../routes";

export type PermissionsConfigurationParams = { realm: string };

const PermissionsConfigurationSection = lazy(
  () => import("../PermissionsConfigurationSection"),
);

export const PermissionsConfigurationRoute: AppRouteObject = {
  path: "/:realm/permissions",
  element: <PermissionsConfigurationSection />,
  breadcrumb: (t) => t("titlePermissions"),
  handle: {
    access: (accessChecker: { hasAny: (...types: AccessType[]) => boolean }) =>
      accessChecker.hasAny("view-realm", "view-clients", "view-users"),
  },
};

export const toPermissionsConfiguration = (
  params: PermissionsConfigurationParams,
): Partial<Path> => ({
  pathname: generateEncodedPath(PermissionsConfigurationRoute.path, params),
});



