import { IamshieldAdminClient } from "./client.js";
import { RequiredActionAlias } from "./defs/requiredActionProviderRepresentation.js";

export const requiredAction = RequiredActionAlias;
export default IamshieldAdminClient;
export { NetworkError, fetchWithError } from "./utils/fetchWithError.js";
export type { NetworkErrorOptions } from "./utils/fetchWithError.js";
