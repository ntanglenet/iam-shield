import type ComponentRepresentation from "@iamshield/iamshield-admin-client/lib/defs/componentRepresentation";
import {
  Action,
  IamshieldDataTable,
  ListEmptyState,
  useAlerts,
  useFetch,
} from "@iamshield/iamshield-ui-shared";
import {
  AlertVariant,
  Button,
  ButtonVariant,
  ToolbarItem,
} from "@patternfly/react-core";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { Link, To, useNavigate, useParams } from "react-router-dom";
import { useAdminClient } from "../../../admin-client";
import { useConfirmDialog } from "../../../components/confirm-dialog/ConfirmDialog";
import useLocaleSort, { mapByKey } from "../../../utils/useLocaleSort";

export type LdapMapperListProps = {
  toCreate: To;
  toDetail: (mapperId: string) => To;
};

type MapperLinkProps = ComponentRepresentation & {
  toDetail: (mapperId: string) => To;
};

const MapperLink = ({ toDetail, ...mapper }: MapperLinkProps) => (
  <Link to={toDetail(mapper.id!)}>{mapper.name}</Link>
);

export const LdapMapperList = ({ toCreate, toDetail }: LdapMapperListProps) => {
  const { adminClient } = useAdminClient();

  const navigate = useNavigate();
  const { t } = useTranslation();
  const { addAlert, addError } = useAlerts();
  const [key, setKey] = useState(0);
  const refresh = () => setKey(key + 1);

  const [mappers, setMappers] = useState<ComponentRepresentation[]>([]);
  const localeSort = useLocaleSort();

  const { id } = useParams<{ id: string }>();

  const [selectedMapper, setSelectedMapper] =
    useState<ComponentRepresentation>();

  useFetch(
    () =>
      adminClient.components.find({
        parent: id,
        type: "org.iamshield.storage.ldap.mappers.LDAPStorageMapper",
      }),
    (mapper: ComponentRepresentation[]) => {
      setMappers(
        localeSort(
          mapper.map((mapper: ComponentRepresentation) => ({
            ...mapper,
            name: mapper.name,
            type: mapper.providerId,
          })),
          mapByKey("name"),
        ),
      );
    },
    [key],
  );

  const [toggleDeleteDialog, DeleteConfirm] = useConfirmDialog({
    titleKey: t("deleteMappingTitle", { mapperId: selectedMapper?.id }),
    messageKey: "deleteMappingConfirm",
    continueButtonLabel: "delete",
    continueButtonVariant: ButtonVariant.danger,
    onConfirm: async () => {
      try {
        await adminClient.components.del({
          id: selectedMapper!.id!,
        });
        refresh();
        addAlert(t("mappingDeletedSuccess"), AlertVariant.success);
        setSelectedMapper(undefined);
      } catch (error) {
        addError("mappingDeletedError", error);
      }
    },
  });

  return (
    <>
      <DeleteConfirm />
      <IamshieldDataTable
        key={key}
        loader={mappers}
        ariaLabelKey="ldapMappersList"
        searchPlaceholderKey="searchForMapper"
        toolbarItem={
          <ToolbarItem>
            <Button
              data-testid="add-mapper-btn"
              variant="primary"
              component={(props) => <Link {...props} to={toCreate} />}
            >
              {t("addMapper")}
            </Button>
          </ToolbarItem>
        }
        actions={[
          {
            title: t("delete"),
            onRowClick: (mapper: ComponentRepresentation) => {
              setSelectedMapper(mapper);
              toggleDeleteDialog();
            },
          } as Action<ComponentRepresentation>,
        ]}
        columns={[
          {
            name: "name",
            cellRenderer: (row: ComponentRepresentation) => <MapperLink {...row} toDetail={toDetail} />,
          },
          {
            name: "type",
          },
        ]}
        emptyState={
          <ListEmptyState
            message={t("emptyMappers")}
            instructions={t("emptyMappersInstructions")}
            primaryActionText={t("emptyPrimaryAction")}
            onPrimaryAction={() => navigate(toCreate)}
          />
        }
      />
    </>
  );
};
