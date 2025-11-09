import type ClientPolicyRepresentation from "./clientPolicyRepresentation.js";

/**
 * https://www.iamshield.org/docs-api/15.0/rest-api/#_clientpoliciesrepresentation
 */
export default interface ClientPoliciesRepresentation {
  globalPolicies?: ClientPolicyRepresentation[];
  policies?: ClientPolicyRepresentation[];
}
