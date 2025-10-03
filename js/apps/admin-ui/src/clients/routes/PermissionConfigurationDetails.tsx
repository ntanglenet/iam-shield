import { lazy } from "react";
import type { Path } from "react-router-dom";
import type { AccessType } from "@iamshield/iamshield-admin-client/lib/defs/whoAmIRepresentation";
import { generateEncodedPath } from "../../utils/generateEncodedPath";
import type { AppRouteObject } from "../../routes";

export type PermissionConfigurationDetailParams = {
  realm: string;
  id: string;
  permissionId: string;
  permissionType: string;
};

const PermissionConfigurationDetails = lazy(
  () =>
    import(
      "../../permissions-configuration/permission-configuration/PermissionConfigurationDetails"
    ),
);

export const PermissionConfigurationDetailRoute: AppRouteObject = {
  path: "/:realm/clients/:id/permissions/permission/:permissionId/:permissionType",
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
  params: PermissionConfigurationDetailParams,
): Partial<Path> => ({
  pathname: generateEncodedPath(
    PermissionConfigurationDetailRoute.path,
    params,
  ),
});
