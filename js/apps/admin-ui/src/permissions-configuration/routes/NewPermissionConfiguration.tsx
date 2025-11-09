import { lazy } from "react";
import type { Path } from "react-router-dom";
import type { AccessType } from "@iamshield/iamshield-admin-client/lib/defs/whoAmIRepresentation";
import { generateEncodedPath } from "../../utils/generateEncodedPath";
import type { AppRouteObject } from "../../routes";

export type NewPermissionConfigurationParams = {
  realm: string;
  permissionClientId: string;
  resourceType: string;
};

const PermissionConfigurationDetails = lazy(
  () => import("../permission-configuration/PermissionConfigurationDetails"),
);

export const NewPermissionConfigurationRoute: AppRouteObject = {
  path: "/:realm/permissions/:permissionClientId/permission/new/:resourceType",
  element: <PermissionConfigurationDetails />,
  breadcrumb: (t) => t("createPermission"),
  handle: {
    access: (accessChecker: { hasAny: (...types: AccessType[]) => boolean }) =>
      accessChecker.hasAny("manage-clients", "manage-authorization"),
  },
};

export const toCreatePermissionConfiguration = (
  params: NewPermissionConfigurationParams,
): Partial<Path> => ({
  pathname: generateEncodedPath(NewPermissionConfigurationRoute.path, params),
});



