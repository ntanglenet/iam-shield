import type RequiredActionProviderRepresentation from "@iamshield/iamshield-admin-client/lib/defs/requiredActionProviderRepresentation";
import {
  SelectControl,
  SelectVariant,
  useFetch,
} from "@iamshield/iamshield-ui-shared";
import { useState } from "react";
import { FieldPathByValue, FieldValues } from "react-hook-form";
import { useTranslation } from "react-i18next";
import { useAdminClient } from "../../admin-client";

export type RequiredActionMultiSelectProps<
  T extends FieldValues,
  P extends FieldPathByValue<T, string[] | undefined>,
> = {
  name: P;
  label: string;
  help: string;
};

export const RequiredActionMultiSelect = <
  T extends FieldValues,
  P extends FieldPathByValue<T, string[] | undefined>,
>({
  name,
  label,
  help,
}: RequiredActionMultiSelectProps<T, P>) => {
  const { adminClient } = useAdminClient();

  const { t } = useTranslation();
  const [requiredActions, setRequiredActions] = useState<
    RequiredActionProviderRepresentation[]
  >([]);

  useFetch(
    () => adminClient.authenticationManagement.getRequiredActions(),
    (actions: RequiredActionProviderRepresentation[]) => {
      const enabledUserActions = actions.filter((action: RequiredActionProviderRepresentation) => {
        return action.enabled;
      });
      setRequiredActions(enabledUserActions);
    },
    [],
  );

  return (
    <SelectControl
      name={name}
      label={t(label)}
      labelIcon={t(help)}
      controller={{ defaultValue: [] }}
      isScrollable
      maxMenuHeight="375px"
      variant={SelectVariant.typeaheadMulti}
      chipGroupProps={{
        numChips: 3,
      }}
      placeholderText={t("requiredActionPlaceholder")}
      menuAppendTo="parent"
      options={requiredActions.map(({ alias, name }) => ({
        key: alias!,
        value: name || alias!,
      }))}
    />
  );
};
