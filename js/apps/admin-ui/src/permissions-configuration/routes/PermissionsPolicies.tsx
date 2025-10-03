import { lazy } from "react";
import type { Path } from "react-router-dom";
import type { AccessType } from "@iamshield/iamshield-admin-client/lib/defs/whoAmIRepresentation";
import { generateEncodedPath } from "../../utils/generateEncodedPath";
import type { AppRouteObject } from "../../routes";

export type PermissionsPoliciesParams = {
  realm: string;
  permissionClientId: string;
};

const PermissionsPoliciesSection = lazy(
  () => import("../PermissionsConfigurationSection"),
);

export const PermissionsPoliciesRoute: AppRouteObject = {
  path: "/:realm/permissions/:permissionClientId/policies",
  element: <PermissionsPoliciesSection />,
  breadcrumb: (t) => t("policies"),
  handle: {
    access: (accessChecker: { hasAny: (...types: AccessType[]) => boolean }) =>
      accessChecker.hasAny("view-realm", "view-clients", "view-users"),
  },
};

export const toPermissionsPolicies = (
  params: PermissionsPoliciesParams,
): Partial<Path> => ({
  pathname: generateEncodedPath(PermissionsPoliciesRoute.path, params),
});



