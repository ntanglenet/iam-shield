import {
  Avatar,
  AvatarProps,
  DropdownItem,
  Masthead,
  MastheadBrand,
  MastheadBrandProps,
  MastheadContent,
  MastheadMainProps,
  MastheadToggle,
  PageToggleButton,
  Toolbar,
  ToolbarContent,
  ToolbarItem,
} from "@patternfly/react-core";
import { BarsIcon } from "@patternfly/react-icons";
import { TFunction } from "i18next";
import Keycloak, { type KeycloakTokenParsed } from "keycloak-js";
import { ReactNode } from "react";
import { useTranslation } from "react-i18next";
import { DefaultAvatar } from "./DefaultAvatar";
import { IamshieldDropdown } from "./IamshieldDropdown";

function loggedInUserName(
  token: KeycloakTokenParsed | undefined,
  t: TFunction,
) {
  if (!token) {
    return t("unknownUser");
  }

  const givenName = token.given_name;
  const familyName = token.family_name;
  const preferredUsername = token.preferred_username;

  if (givenName && familyName) {
    return t("fullName", { givenName, familyName });
  }

  return givenName || familyName || preferredUsername || t("unknownUser");
}

type BrandLogo = MastheadBrandProps;

type IamshieldMastheadProps = MastheadMainProps & {
  iamshield: Keycloak;
  brand: BrandLogo;
  avatar?: AvatarProps;
  features?: {
    hasLogout?: boolean;
    hasManageAccount?: boolean;
    hasUsername?: boolean;
  };
  kebabDropdownItems?: ReactNode[];
  dropdownItems?: ReactNode[];
  toolbarItems?: ReactNode[];
  toolbar?: ReactNode;
};

const IamshieldMasthead = ({
  iamshield,
  brand: { src, alt, className, ...brandProps },
  avatar,
  features: {
    hasLogout = true,
    hasManageAccount = true,
    hasUsername = true,
  } = {},
  kebabDropdownItems,
  dropdownItems = [],
  toolbarItems,
  toolbar,
  ...rest
}: IamshieldMastheadProps) => {
  const { t } = useTranslation();
  const extraItems = [];
  if (hasManageAccount) {
    extraItems.push(
      <DropdownItem
        key="manageAccount"
        onClick={() => iamshield.accountManagement()}
      >
        {t("manageAccount")}
      </DropdownItem>,
    );
  }
  if (hasLogout) {
    extraItems.push(
      <DropdownItem key="signOut" onClick={() => iamshield.logout()}>
        {t("signOut")}
      </DropdownItem>,
    );
  }

  const picture = iamshield.idTokenParsed?.picture;
  return (
    <Masthead {...rest}>
      <MastheadToggle>
        <PageToggleButton variant="plain" aria-label={t("navigation")}>
          <BarsIcon />
        </PageToggleButton>
      </MastheadToggle>
      <MastheadBrand {...brandProps}>
        <img src={src} alt={alt} className={className} />
      </MastheadBrand>
      <MastheadContent>
        {toolbar}
        <Toolbar>
          <ToolbarContent>
            {toolbarItems?.map((item, index) => (
              <ToolbarItem key={index} align={{ default: "alignRight" }}>
                {item}
              </ToolbarItem>
            ))}
            <ToolbarItem
              visibility={{
                default: "hidden",
                md: "visible",
              }} /** this user dropdown is hidden on mobile sizes */
            >
              <IamshieldDropdown
                data-testid="options"
                dropDownItems={[...dropdownItems, extraItems]}
                title={
                  hasUsername
                    ? loggedInUserName(iamshield.idTokenParsed, t)
                    : undefined
                }
              />
            </ToolbarItem>
            <ToolbarItem
              align={{ default: "alignLeft" }}
              visibility={{
                md: "hidden",
              }}
            >
              <IamshieldDropdown
                data-testid="options-kebab"
                isKebab
                dropDownItems={[
                  ...(kebabDropdownItems || dropdownItems),
                  extraItems,
                ]}
              />
            </ToolbarItem>
            <ToolbarItem
              variant="overflow-menu"
              align={{ default: "alignRight" }}
              className="pf-v5-u-m-0-on-lg"
            >
              {picture || avatar?.src ? (
                <Avatar {...{ src: picture, alt: t("avatar"), ...avatar }} />
              ) : (
                <DefaultAvatar {...avatar} />
              )}
            </ToolbarItem>
          </ToolbarContent>
        </Toolbar>
      </MastheadContent>
    </Masthead>
  );
};

export default IamshieldMasthead;
