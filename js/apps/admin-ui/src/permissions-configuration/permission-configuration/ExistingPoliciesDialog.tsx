import PolicyRepresentation from "@iamshield/iamshield-admin-client/lib/defs/policyRepresentation";
import { PolicyQuery } from "@iamshield/iamshield-admin-client/lib/resources/clients";
import {
  IamshieldDataTable,
  ListEmptyState,
  useFetch,
} from "@iamshield/iamshield-ui-shared";
import {
  Button,
  ButtonVariant,
  Dropdown,
  DropdownItem,
  DropdownList,
  MenuToggle,
  Modal,
  ModalVariant,
} from "@patternfly/react-core";
import { CaretDownIcon, FilterIcon } from "@patternfly/react-icons";
import { sortBy } from "lodash-es";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { useAdminClient } from "../../admin-client";
import { capitalizeFirstLetterFormatter } from "../../util";
import useToggle from "../../utils/useToggle";
import PolicyProviderRepresentation from "@iamshield/iamshield-admin-client/lib/defs/policyProviderRepresentation";

export type ExistingPoliciesDialogProps = {
  toggleDialog: () => void;
  onAssign: (policies: { policy: PolicyRepresentation }[]) => void;
  open: boolean;
  permissionClientId: string;
};

export const ExistingPoliciesDialog = ({
  toggleDialog,
  onAssign,
  open,
  permissionClientId,
}: ExistingPoliciesDialogProps) => {
  const { t } = useTranslation();
  const { adminClient } = useAdminClient();
  const [rows, setRows] = useState<PolicyRepresentation[]>([]);
  const [filterType, setFilterType] = useState<string | undefined>(undefined);
  const [isFilterTypeDropdownOpen, toggleIsFilterTypeDropdownOpen] =
    useToggle();
  const [providers, setProviders] = useState<string[]>([]);

  useFetch(
    () =>
      adminClient.clients.listPolicyProviders({
        id: permissionClientId!,
      }),
    (providers: PolicyProviderRepresentation[]) => {
      const formattedProviders = providers
        .filter((p) => p.type !== "resource" && p.type !== "scope")
        .map((provider) => provider.name)
        .filter((name) => name !== undefined);
      setProviders(sortBy(formattedProviders));
    },
    [permissionClientId],
  );

  const loader = async (first?: number, max?: number, search?: string) => {
    const params: PolicyQuery = {
      id: permissionClientId!,
      permission: "false",
      first,
      max,
    };

    if (search) {
      params.name = search;
    }

    if (filterType) {
      params.type = filterType;
    }

    return (await adminClient.clients.listPolicies(params)) || [];
  };

  return (
    <Modal
      variant={ModalVariant.medium}
      title={t("assignExistingPolicies")}
      isOpen={open}
      onClose={toggleDialog}
      actions={[
        <>
          <Button
            id="modal-assignExistingPolicies"
            data-testid="confirm"
            key="assign"
            variant={ButtonVariant.primary}
            onClick={() => {
              const selectedPolicies = rows.map((policy) => ({ policy }));
              onAssign(selectedPolicies);
              toggleDialog();
            }}
            isDisabled={rows.length === 0}
          >
            {t("assign")}
          </Button>
          <Button
            id="modal-cancelExistingPolicies"
            data-testid="cancel"
            key="cancel"
            variant={ButtonVariant.link}
            onClick={() => {
              setRows([]);
              toggleDialog();
            }}
          >
            {t("cancel")}
          </Button>
        </>,
      ]}
    >
      <IamshieldDataTable
        key={filterType}
        loader={loader}
        ariaLabelKey={t("chooseAPolicyType")}
        searchPlaceholderKey={t("searchClientAuthorizationPolicy")}
        isSearching={true}
        searchTypeComponent={
          <Dropdown
            onSelect={(_, value) => {
              setFilterType(value as string | undefined);
              toggleIsFilterTypeDropdownOpen();
            }}
            onOpenChange={toggleIsFilterTypeDropdownOpen}
            toggle={(ref) => (
              <MenuToggle
                ref={ref}
                data-testid="filter-type-dropdown-existingPolicies"
                id="toggle-id-10"
                onClick={toggleIsFilterTypeDropdownOpen}
                icon={<FilterIcon />}
                statusIcon={<CaretDownIcon />}
              >
                {filterType ? filterType : t("allTypes")}
              </MenuToggle>
            )}
            isOpen={isFilterTypeDropdownOpen}
          >
            <DropdownList>
              <DropdownItem
                data-testid="filter-type-dropdown-existingPolicies-all"
                key="all"
                onClick={() => setFilterType(undefined)}
              >
                {t("allTypes")}
              </DropdownItem>
              {providers.map((name) => (
                <DropdownItem
                  data-testid={`filter-type-dropdown-existingPolicies-${name}`}
                  key={name}
                  onClick={() => setFilterType(name)}
                >
                  {name}
                </DropdownItem>
              ))}
            </DropdownList>
          </Dropdown>
        }
        canSelectAll
        onSelect={(selectedRows: PolicyRepresentation[]) => setRows(selectedRows)}
        columns={[
          { name: "name" },
          {
            name: "type",
            cellFormatters: [capitalizeFirstLetterFormatter()],
          },
          { name: "description" },
        ]}
        emptyState={
          <ListEmptyState
            message={t("emptyAssignExistingPolicies")}
            instructions={t("emptyAssignExistingPoliciesInstructions")}
          />
        }
      />
    </Modal>
  );
};
