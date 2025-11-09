import { lazy } from "react";
import type { Path } from "react-router-dom";
import type { AccessType } from "@iamshield/iamshield-admin-client/lib/defs/whoAmIRepresentation";
import { generateEncodedPath } from "../../utils/generateEncodedPath";
import type { AppRouteObject } from "../../routes";

export type PolicyDetailsParams = {
  realm: string;
  id: string;
  policyId: string;
  policyType: string;
};

const PolicyDetails = lazy(
  () => import("../authorization/policy/PolicyDetails"),
);

export const PolicyDetailsRoute: AppRouteObject = {
  path: "/:realm/clients/:id/authorization/policy/:policyId/:policyType",
  element: <PolicyDetails />,
  breadcrumb: (t) => t("policyDetails"),
  handle: {
    access: (accessChecker: { hasAny: (...types: AccessType[]) => boolean }) =>
      accessChecker.hasAny(
        "manage-clients",
        "view-authorization",
        "manage-authorization",
      ),
  },
};

export const toPolicyDetails = (
  params: PolicyDetailsParams,
): Partial<Path> => ({
  pathname: generateEncodedPath(PolicyDetailsRoute.path, params),
});


