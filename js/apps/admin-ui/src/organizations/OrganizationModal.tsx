import OrganizationRepresentation from "@iamshield/iamshield-admin-client/lib/defs/organizationRepresentation";
import UserRepresentation from "@iamshield/iamshield-admin-client/lib/defs/userRepresentation";
import { IamshieldDataTable } from "@iamshield/iamshield-ui-shared";
import { Button, Modal, ModalVariant } from "@patternfly/react-core";
import { TableText } from "@patternfly/react-table";
import { differenceBy } from "lodash-es";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { useAdminClient } from "../admin-client";

type OrganizationModalProps = {
  isJoin?: boolean;
  existingOrgs: OrganizationRepresentation[];
  onAdd: (orgs: OrganizationRepresentation[]) => Promise<void>;
  onClose: () => void;
};

export const OrganizationModal = ({
  isJoin = true,
  existingOrgs,
  onAdd,
  onClose,
}: OrganizationModalProps) => {
  const { adminClient } = useAdminClient();
  const { t } = useTranslation();

  const [selectedRows, setSelectedRows] = useState<OrganizationRepresentation[]>([]);

  const loader = async (
    first?: number,
    max?: number,
    search?: string,
  ): Promise<OrganizationRepresentation[]> => {
    const params = {
      first,
      search,
      max: max! + existingOrgs.length,
    };

    const orgs: OrganizationRepresentation[] = await adminClient.organizations.find(
      params,
    );
    const uniqueOrgs = orgs.filter(
      (o: OrganizationRepresentation) => !existingOrgs.some((e) => e.id === o.id),
    );
    return uniqueOrgs;
  };

  return (
    <Modal
      variant={ModalVariant.small}
      title={isJoin ? t("joinOrganization") : t("sendInvitation")}
      isOpen
      onClose={onClose}
      actions={[
        <Button
          data-testid="join"
          key="confirm"
          variant="primary"
          onClick={async () => {
            await onAdd(selectedRows);
            onClose();
          }}
        >
          {isJoin ? t("join") : t("send")}
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
        ariaLabelKey="organizationsList"
        searchPlaceholderKey="searchOrganization"
        canSelectAll
        onSelect={(rows: OrganizationRepresentation[]) => setSelectedRows([...rows])}
        columns={[
          {
            name: "name",
            displayKey: "organizationName",
          },
          {
            name: "description",
            cellRenderer: (row: OrganizationRepresentation) => (
              <TableText wrapModifier="truncate">{row.description}</TableText>
            ),
          },
        ]}
      />
    </Modal>
  );
};
