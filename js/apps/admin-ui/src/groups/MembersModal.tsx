import type UserRepresentation from "@iamshield/iamshield-admin-client/lib/defs/userRepresentation";
import { Button, Modal, ModalVariant, Label } from "@patternfly/react-core";
import { InfoCircleIcon } from "@patternfly/react-icons";
import { differenceBy } from "lodash-es";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { useAdminClient } from "../admin-client";
import { useAlerts } from "@iamshield/iamshield-ui-shared";
import { ListEmptyState } from "@iamshield/iamshield-ui-shared";
import { IamshieldDataTable } from "@iamshield/iamshield-ui-shared";
import { emptyFormatter } from "../util";

type MemberModalProps = {
  membersQuery: (first?: number, max?: number) => Promise<UserRepresentation[]>;
  onAdd: (users: UserRepresentation[]) => Promise<void>;
  onClose: () => void;
};

const UserDetail = (user: UserRepresentation) => {
  const { t } = useTranslation();
  return (
    <>
      {user.username}{" "}
      {!user.enabled && (
        <Label color="red" icon={<InfoCircleIcon />}>
          {t("disabled")}
        </Label>
      )}
    </>
  );
};

export const MemberModal = ({
  membersQuery,
  onAdd,
  onClose,
}: MemberModalProps) => {
  const { adminClient } = useAdminClient();

  const { t } = useTranslation();
  const { addError } = useAlerts();
  const [selectedRows, setSelectedRows] = useState<UserRepresentation[]>([]);

  const loader = async (
    first?: number,
    max?: number,
    search?: string,
  ): Promise<UserRepresentation[]> => {
    const members = await membersQuery(first, max);
    const params: { [name: string]: string | number } = {
      first: first!,
      max: max! + members.length,
      search: search || "",
    };

    try {
      const users: UserRepresentation[] = await adminClient.users.find({
        ...params,
      });
      const uniqueUsers = users.filter(
        (u: UserRepresentation) => !members.some((m) => m.id === u.id),
      );
      return uniqueUsers.slice(0, max);
    } catch (error) {
      addError("noUsersFoundError", error);
      return [];
    }
  };

  return (
    <Modal
      variant={ModalVariant.large}
      title={t("addMember")}
      isOpen
      onClose={onClose}
      actions={[
        <Button
          data-testid="add"
          key="confirm"
          variant="primary"
          onClick={async () => {
            await onAdd(selectedRows);
            onClose();
          }}
        >
          {t("add")}
        </Button>,
        <Button
          data-testid="cancel"
          key="cancel"
          variant="link"
          onClick={onClose}
        >
          {t("cancel")}
        </Button>,
      ]}
    >
      <IamshieldDataTable
        loader={loader}
        isPaginated
        ariaLabelKey="titleUsers"
        searchPlaceholderKey="searchForUser"
        canSelectAll
        onSelect={(rows: UserRepresentation[]) => setSelectedRows([...rows])}
        emptyState={
          <ListEmptyState
            message={t("noUsersFound")}
            instructions={t("emptyInstructions")}
          />
        }
        columns={[
          {
            name: "username",
            displayKey: "username",
            cellRenderer: UserDetail,
          },
          {
            name: "email",
            displayKey: "email",
            cellFormatters: [emptyFormatter()],
          },
          {
            name: "lastName",
            displayKey: "lastName",
            cellFormatters: [emptyFormatter()],
          },
          {
            name: "firstName",
            displayKey: "firstName",
            cellFormatters: [emptyFormatter()],
          },
        ]}
      />
    </Modal>
  );
};
