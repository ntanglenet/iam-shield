import type ScopeRepresentation from "@iamshield/iamshield-admin-client/lib/defs/scopeRepresentation";
import {
  FormErrorText,
  HelpItem,
  IamshieldSelect,
  SelectVariant,
  useFetch,
} from "@iamshield/iamshield-ui-shared";
import { FormGroup, SelectOption } from "@patternfly/react-core";
import { useState } from "react";
import { Controller, useFormContext } from "react-hook-form";
import { useTranslation } from "react-i18next";
import { useAdminClient } from "../../admin-client";
import { IamshieldSpinner } from "@iamshield/iamshield-ui-shared";
import { useIsAdminPermissionsClient } from "../../utils/useIsAdminPermissionsClient";

type Scope = {
  id: string;
  name: string;
};

type ScopePickerProps = {
  clientId: string;
  resourceTypeScopes?: string[];
};

export const ScopePicker = ({
  clientId,
  resourceTypeScopes,
}: ScopePickerProps) => {
  const { adminClient } = useAdminClient();
  const { t } = useTranslation();
  const {
    control,
    formState: { errors },
  } = useFormContext();
  const [open, setOpen] = useState(false);
  const [scopes, setScopes] = useState<ScopeRepresentation[]>();
  const [search, setSearch] = useState("");
  const isAdminPermissionsClient = useIsAdminPermissionsClient(clientId);

  useFetch(
    () => {
      const params = {
        id: clientId,
        first: 0,
        max: 20,
        deep: false,
        name: search,
      };
      return adminClient.clients.listAllScopes(params);
    },
    setScopes,
    [search],
  );

  const renderScopes = (scopes: ScopeRepresentation[] | string[]) =>
    scopes.map((option, index) => (
      <SelectOption key={index} value={option}>
        {typeof option === "string" ? option : option.name}
      </SelectOption>
    ));

  if (!scopes && !resourceTypeScopes) return <IamshieldSpinner />;

  const allScopes =
    isAdminPermissionsClient && resourceTypeScopes
      ? resourceTypeScopes
      : scopes?.map((scope) => scope.name!);

  return (
    <FormGroup
      label={t("authorizationScopes")}
      labelIcon={
        <HelpItem helpText={t("clientScopesHelp")} fieldLabelId="scopes" />
      }
      fieldId="scopes"
      isRequired={isAdminPermissionsClient}
    >
      <Controller
        name="scopes"
        defaultValue={[]}
        control={control}
        rules={isAdminPermissionsClient ? { required: t("requiredField") } : {}}
        render={({ field }) => {
          const selectedValues = field.value.map((o: Scope) => o.name);
          return (
            <>
              <IamshieldSelect
                toggleId="scopes"
                variant={SelectVariant.typeaheadMulti}
                chipGroupProps={{
                  numChips: 3,
                  expandedText: t("hide"),
                  collapsedText: t("showRemaining"),
                }}
                onToggle={(val) => setOpen(val)}
                isOpen={open}
                selections={selectedValues}
                onFilter={(value) => {
                  setSearch(value);
                  return renderScopes(allScopes || []);
                }}
                onSelect={(selectedValue) => {
                  const option =
                    typeof selectedValue === "string"
                      ? selectedValue
                      : (selectedValue as Scope).name;
                  const changedValue = field.value.find(
                    (o: Scope) => o.name === option,
                  )
                    ? field.value.filter((item: Scope) => item.name !== option)
                    : [...field.value, { name: option }];
                  field.onChange(changedValue);
                }}
                onClear={() => {
                  setSearch("");
                  field.onChange([]);
                }}
                typeAheadAriaLabel={t("authorizationScopes")}
              >
                {renderScopes(allScopes || [])}
              </IamshieldSelect>
              {isAdminPermissionsClient && errors.scopes && (
                <FormErrorText message={t("required")} />
              )}
            </>
          );
        }}
      />
    </FormGroup>
  );
};
