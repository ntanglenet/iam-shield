import UserRepresentation from "@iamshield/iamshield-admin-client/lib/defs/userRepresentation";
import { useFetch } from "@iamshield/iamshield-ui-shared";
import { useState } from "react";
import { useAdminClient } from "../admin-client";
import { useWhoAmI } from "../context/whoami/WhoAmI";

export function useCurrentUser() {
  const { adminClient } = useAdminClient();
  const { whoAmI } = useWhoAmI();
  const [currentUser, setCurrentUser] = useState<UserRepresentation>();

  useFetch(
    () => adminClient.users.findOne({ id: whoAmI.userId }),
    setCurrentUser,
    [whoAmI.userId],
  );

  return { ...currentUser, realm: whoAmI.realm };
}
