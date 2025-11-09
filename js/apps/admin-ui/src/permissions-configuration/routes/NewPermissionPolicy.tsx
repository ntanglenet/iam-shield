import { lazy } from "react";
import type { Path } from "react-router-dom";
import type { AccessType } from "@iamshield/iamshield-admin-client/lib/defs/whoAmIRepresentation";
import { generateEncodedPath } from "../../utils/generateEncodedPath";
import type { AppRouteObject } from "../../routes";

export type NewPermissionPolicyDetailsParams = {
  realm: string;
  permissionClientId: string;
  policyType: string;
};

const NewPermissionPolicyDetails = lazy(
  () => import("../../clients/authorization/policy/PolicyDetails"),
);

export const NewPermissionPolicyRoute: AppRouteObject = {
  path: "/:realm/permissions/:permissionClientId/policies/new/:policyType",
  element: <NewPermissionPolicyDetails />,
  breadcrumb: (t) => t("createPermissionPolicy"),
  handle: {
    access: (accessChecker: { hasAny: (...types: AccessType[]) => boolean }) =>
      accessChecker.hasAny("manage-clients", "manage-authorization"),
  },
};

export const toCreatePermissionPolicy = (
  params: NewPermissionPolicyDetailsParams,
): Partial<Path> => ({
  pathname: generateEncodedPath(NewPermissionPolicyRoute.path, params),
});



