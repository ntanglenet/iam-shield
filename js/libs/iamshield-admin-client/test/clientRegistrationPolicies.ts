import * as chai from "chai";
import { IamshieldAdminClient } from "../src/client.js";
import { credentials } from "./constants.js";

const expect = chai.expect;

describe("Client Registration Policies", () => {
  let client: IamshieldAdminClient;

  before(async () => {
    client = new IamshieldAdminClient();
    await client.auth(credentials);
  });

  it("list client registration policies", async () => {
    const clientRegistrationPolicies =
      await client.clientRegistrationPolicies.find();
    expect(clientRegistrationPolicies).to.be.ok;
  });
});
