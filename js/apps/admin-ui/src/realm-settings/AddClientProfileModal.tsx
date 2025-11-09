import type ClientProfileRepresentation from "@iamshield/iamshield-admin-client/lib/defs/clientProfileRepresentation";
import type RoleRepresentation from "@iamshield/iamshield-admin-client/lib/defs/roleRepresentation";
import { IamshieldDataTable, useFetch } from "@iamshield/iamshield-ui-shared";
import { Button, Label, Modal, ModalVariant } from "@patternfly/react-core";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { useAdminClient } from "../admin-client";
import { IamshieldSpinner } from "@iamshield/iamshield-ui-shared";
import { ListEmptyState } from "@iamshield/iamshield-ui-shared";
import { translationFormatter } from "../utils/translationFormatter";

type ClientProfile = ClientProfileRepresentation & {
  global: boolean;
};

const AliasRenderer = ({ name, global }: ClientProfile) => {
  const { t } = useTranslation();

  return (
    <>
      {name} {global && <Label color="blue">{t("global")}</Label>}
    </>
  );
};

export type AddClientProfileModalProps = {
  open: boolean;
  toggleDialog: () => void;
  onConfirm: (newReps: RoleRepresentation[]) => void;
  allProfiles: string[];
};

export const AddClientProfileModal = (props: AddClientProfileModalProps) => {
  const { adminClient } = useAdminClient();

  const { t } = useTranslation();
  const [selectedRows, setSelectedRows] = useState<RoleRepresentation[]>([]);

  const [tableProfiles, setTableProfiles] = useState<ClientProfile[]>();

  useFetch(
    () =>
      adminClient.clientPolicies.listProfiles({
        includeGlobalProfiles: true,
      }),
    (
      allProfiles: {
        globalProfiles?: ClientProfileRepresentation[];
        profiles?: ClientProfileRepresentation[];
      },
    ) => {
      const globalProfiles = allProfiles.globalProfiles?.map(
        (gp: ClientProfileRepresentation) => ({
          id: gp.name,
          ...gp,
          global: true,
        }),
      );

      const profiles = allProfiles.profiles?.map((p: ClientProfileRepresentation) => ({
        ...p,
        global: false,
      }));

      setTableProfiles([...(globalProfiles ?? []), ...(profiles ?? [])]);
    },
    [],
  );

  const loader = async () =>
    tableProfiles?.filter((item) => !props.allProfiles.includes(item.name!)) ??
    [];

  if (!tableProfiles) {
    return <IamshieldSpinner />;
  }

  return (
    <Modal
      data-testid="addClientProfile"
      title={t("addClientProfile")}
      isOpen={props.open}
      onClose={props.toggleDialog}
      variant={ModalVariant.large}
      actions={[
        <Button
          key="add"
          data-testid="add-client-profile-button"
          variant="primary"
          isDisabled={!selectedRows.length}
          onClick={() => {
            props.toggleDialog();
            props.onConfirm(selectedRows);
          }}
        >
          {t("add")}
        </Button>,
        <Button
          key="cancel"
          variant="link"
          onClick={() => {
            props.toggleDialog();
          }}
        >
          {t("cancel")}
        </Button>,
      ]}
    >
      <IamshieldDataTable
        loader={loader}
        ariaLabelKey="profilesList"
        searchPlaceholderKey="searchProfile"
        canSelectAll
        onSelect={(rows) => {
          setSelectedRows([...rows]);
        }}
        columns={[
          {
            name: "name",
            displayKey: "clientProfileName",
            cellRenderer: AliasRenderer,
          },
          {
            name: "description",
            cellFormatters: [translationFormatter(t)],
          },
        ]}
        emptyState={
          <ListEmptyState
            hasIcon
            message={t("noRoles")}
            instructions={t("noRolesInstructions")}
            primaryActionText={t("createRole")}
          />
        }
      />
    </Modal>
  );
};
