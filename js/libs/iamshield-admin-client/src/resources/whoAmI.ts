import type WhoAmIRepresentation from "../defs/whoAmIRepresentation.js";
import type IamshieldAdminClient from "../index.js";
import Resource from "./resource.js";

export class WhoAmI extends Resource<{ realm?: string }> {
  constructor(client: IamshieldAdminClient) {
    super(client, {
      path: "/admin/{realm}/console",
      getUrlParams: () => ({
        realm: client.realmName,
      }),
      getBaseUrl: () => client.baseUrl,
    });
  }

  public find = this.makeRequest<
    { currentRealm: string },
    WhoAmIRepresentation
  >({
    method: "GET",
    path: "/whoami",
    queryParamKeys: ["currentRealm"],
  });
}
