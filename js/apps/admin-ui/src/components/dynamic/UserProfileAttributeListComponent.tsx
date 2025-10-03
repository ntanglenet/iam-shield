import type { UserProfileConfig } from "@iamshield/iamshield-admin-client/lib/defs/userProfileMetadata";
import {
  FormErrorText,
  HelpItem,
  useFetch,
} from "@iamshield/iamshield-ui-shared";
import { FormGroup } from "@patternfly/react-core";
import { useState } from "react";
import { useFormContext } from "react-hook-form";
import { useTranslation } from "react-i18next";
import { useAdminClient } from "../../admin-client";
import { IamSelect } from "../../realm-settings/user-profile/attribute/IamSelect";
import type { ComponentProps } from "./components";

export const UserProfileAttributeListComponent = ({
  name,
  label,
  helpText,
  required = false,
  convertToName,
}: ComponentProps) => {
  const { adminClient } = useAdminClient();

  const { t } = useTranslation();
  const {
    formState: { errors },
  } = useFormContext();

  const [config, setConfig] = useState<UserProfileConfig>();
  const convertedName = convertToName(name!);

  useFetch(
    () => adminClient.users.getProfile(),
    (cfg: UserProfileConfig) => setConfig(cfg),
    [],
  );

  const convert = (config?: UserProfileConfig) => {
    if (!config?.attributes) return [];

    return config.attributes.map((option) => ({
      key: option.name!,
      value: option.name!,
    }));
  };

  if (!config) return null;

  const getError = () => {
    return convertedName
      .split(".")
      .reduce((record: any, key) => record?.[key], errors);
  };

  return (
    <FormGroup
      label={t(label!)}
      isRequired={required}
      labelIcon={<HelpItem helpText={t(helpText!)} fieldLabelId={label!} />}
      fieldId={convertedName!}
    >
      <IamSelect
        name={convertedName}
        rules={required ? { required: true } : {}}
        selectItems={convert(config)}
      />
      {getError() && <FormErrorText message={t("required")} />}
    </FormGroup>
  );
};
