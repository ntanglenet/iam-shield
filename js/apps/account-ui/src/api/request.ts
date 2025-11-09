import {
  IamshieldContext,
  type BaseEnvironment,
} from "@iamshield/iamshield-ui-shared";
import type Keycloak from "keycloak-js";

import { joinPath } from "../utils/joinPath";
import { CONTENT_TYPE_HEADER, CONTENT_TYPE_JSON } from "./constants";

export type RequestOptions = {
  signal?: AbortSignal;
  getAccessToken?: () => Promise<string | undefined>;
  method?: "POST" | "PUT" | "DELETE";
  searchParams?: Record<string, string>;
  body?: unknown;
};

async function _request(
  url: URL,
  { signal, getAccessToken, method, searchParams, body }: RequestOptions = {},
): Promise<Response> {
  if (searchParams) {
    Object.entries(searchParams).forEach(([key, value]) =>
      url.searchParams.set(key, value),
    );
  }

  return fetch(url, {
    signal,
    method,
    body: body ? JSON.stringify(body) : undefined,
    headers: {
      [CONTENT_TYPE_HEADER]: CONTENT_TYPE_JSON,
      authorization: `Bearer ${await getAccessToken?.()}`,
    },
  });
}

export async function request(
  path: string,
  { environment, Iamshield }: IamshieldContext<BaseEnvironment>,
  opts: RequestOptions = {},
  fullUrl?: URL,
) {
  if (typeof fullUrl === "undefined") {
    fullUrl = url(environment, path);
  }
  return _request(fullUrl, {
    ...opts,
    getAccessToken: token(Iamshield),
  });
}

export const url = (environment: BaseEnvironment, path: string) =>
  new URL(
    joinPath(
      environment.serverBaseUrl,
      "realms",
      environment.realm,
      "account",
      path,
    ),
  );

export const token = (iamshield: Keycloak) =>
  async function getAccessToken() {
    try {
      await iamshield.updateToken(5);
    } catch {
      await iamshield.login();
    }

    return iamshield.token;
  };
