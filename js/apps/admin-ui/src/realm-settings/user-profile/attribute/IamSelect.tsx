import {
  IamshieldSelect,
  SelectControlOption,
} from "@iamshield/iamshield-ui-shared";
import {
  Grid,
  GridItem,
  SelectOption,
  TextInput,
} from "@patternfly/react-core";
import { useState } from "react";
import { UseControllerProps, useController } from "react-hook-form";
import { useTranslation } from "react-i18next";
import useToggle from "../../../utils/useToggle";

type IamSelectProp = UseControllerProps & {
  selectItems: SelectControlOption[];
};

export const IamSelect = ({ selectItems, ...rest }: IamSelectProp) => {
  const { t } = useTranslation();
  const [open, toggle] = useToggle();
  const { field } = useController(rest);
  const [custom, setCustom] = useState(
    !selectItems.map(({ key }) => key).includes(field.value),
  );

  return (
    <Grid>
      <GridItem lg={custom ? 2 : 12}>
        <IamshieldSelect
          onToggle={() => toggle()}
          isOpen={open}
          onSelect={(value) => {
            if (value) {
              setCustom(false);
            }
            field.onChange(value);
            toggle();
          }}
          selections={!custom ? [field.value] : ""}
        >
          {[
            <SelectOption key="custom" onClick={() => setCustom(true)}>
              {t("customAttribute")}
            </SelectOption>,
            ...selectItems.map((item) => (
              <SelectOption key={item.key} value={item.key}>
                {item.value}
              </SelectOption>
            )),
          ]}
        </IamshieldSelect>
      </GridItem>
      {custom && (
        <GridItem lg={10}>
          <TextInput
            id="customValue"
            data-testid={rest.name}
            placeholder={t("keyPlaceholder")}
            value={field.value}
            onChange={field.onChange}
            autoFocus
          />
        </GridItem>
      )}
    </Grid>
  );
};
