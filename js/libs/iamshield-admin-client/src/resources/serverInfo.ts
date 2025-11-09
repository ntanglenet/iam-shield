import Resource from "./resource.js";
import type { ServerInfoRepresentation } from "../defs/serverInfoRepesentation.js";
import type IamshieldAdminClient from "../index.js";
import type EffectiveMessageBundleRepresentation from "../defs/effectiveMessageBundleRepresentation.js";

export interface MessageBundleQuery {
  realm: string;
  theme?: string;
  themeType?: string;
  locale?: string;
  source?: boolean;
}

export class ServerInfo extends Resource {
  constructor(client: IamshieldAdminClient) {
    super(client, {
      path: "/",
      getBaseUrl: () => client.baseUrl,
    });
  }

  public find = this.makeRequest<{}, ServerInfoRepresentation>({
    method: "GET",
    path: "/admin/serverinfo",
  });

  public findEffectiveMessageBundles = this.makeRequest<
    MessageBundleQuery,
    EffectiveMessageBundleRepresentation[]
  >({
    method: "GET",
    path: "/resources/{realm}/{themeType}/{locale}",
    urlParamKeys: ["realm", "themeType", "locale"],
    queryParamKeys: ["theme", "source"],
  });
}
