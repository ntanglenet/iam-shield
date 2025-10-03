import { lazy } from "react";
import type { Path } from "react-router-dom";
import type { AccessType } from "@iamshield/iamshield-admin-client/lib/defs/whoAmIRepresentation";
import { generateEncodedPath } from "../../utils/generateEncodedPath";
import type { AppRouteObject } from "../../routes";

export type PermissionConfigurationDetailsParams = {
  realm: string;
  permissionClientId: string;
  permissionId: string;
  resourceType: string;
};

const PermissionConfigurationDetails = lazy(
  () =>
    import(
      "../../permissions-configuration/permission-configuration/PermissionConfigurationDetails"
    ),
);

export const PermissionConfigurationDetailRoute: AppRouteObject = {
  path: "/:realm/permissions/:permissionClientId/permission/:permissionId/:resourceType",
  element: <PermissionConfigurationDetails />,
  breadcrumb: (t) => t("permissionDetails"),
  handle: {
    access: (accessChecker: { hasAny: (...types: AccessType[]) => boolean }) =>
      accessChecker.hasAny(
        "manage-clients",
        "view-authorization",
        "manage-authorization",
      ),
  },
};

export const toPermissionConfigurationDetails = (
  params: PermissionConfigurationDetailsParams,
): Partial<Path> => ({
  pathname: generateEncodedPath(
    PermissionConfigurationDetailRoute.path,
    params,
  ),
});



