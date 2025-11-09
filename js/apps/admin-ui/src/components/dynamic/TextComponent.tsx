import { FormGroup } from "@patternfly/react-core";
import { useFormContext } from "react-hook-form";
import { useTranslation } from "react-i18next";
import { IamshieldTextArea, HelpItem } from "@iamshield/iamshield-ui-shared";
import type { ComponentProps } from "./components";

export const TextComponent = ({
  name,
  label,
  helpText,
  defaultValue,
  required,
  isDisabled = false,
  convertToName,
}: ComponentProps) => {
  const { t } = useTranslation();
  const { register } = useFormContext();

  return (
    <FormGroup
      label={t(label!)}
      labelIcon={<HelpItem helpText={t(helpText!)} fieldLabelId={`${label}`} />}
      fieldId={name!}
      required={required}
    >
      <IamshieldTextArea
        id={name!}
        data-testid={name}
        isDisabled={isDisabled}
        defaultValue={defaultValue?.toString()}
        {...register(convertToName(name!))}
      />
    </FormGroup>
  );
};
