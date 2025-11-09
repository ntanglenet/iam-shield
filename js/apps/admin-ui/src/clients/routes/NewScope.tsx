import { lazy } from "react";
import type { Path } from "react-router-dom";
import type { AccessType } from "@iamshield/iamshield-admin-client/lib/defs/whoAmIRepresentation";
import { generateEncodedPath } from "../../utils/generateEncodedPath";
import type { AppRouteObject } from "../../routes";

export type NewScopeParams = { realm: string; id: string };

const ScopeDetails = lazy(() => import("../authorization/ScopeDetails"));

export const NewScopeRoute: AppRouteObject = {
  path: "/:realm/clients/:id/authorization/scope/new",
  element: <ScopeDetails />,
  breadcrumb: (t) => t("createAuthorizationScope"),
  handle: {
    access: (accessChecker: { hasAny: (...types: AccessType[]) => boolean }) =>
      accessChecker.hasAny("manage-clients", "manage-authorization"),
  },
};

export const toNewScope = (params: NewScopeParams): Partial<Path> => ({
  pathname: generateEncodedPath(NewScopeRoute.path, params),
});
