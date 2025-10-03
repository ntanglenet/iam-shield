import "@patternfly/patternfly/patternfly-addons.css";
import "@patternfly/react-core/dist/styles/base.css";

import { IamshieldProvider } from "@iamshield/iamshield-ui-shared";
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { environment } from "./environment";
import { i18n } from "./i18n";
import { Root } from "./root/Root";

// Initialize required components before rendering app.
await i18n.init();

const container = document.getElementById("app");
const root = createRoot(container!);

root.render(
  <StrictMode>
    <IamshieldProvider environment={environment}>
      <Root />
    </IamshieldProvider>
  </StrictMode>,
);
