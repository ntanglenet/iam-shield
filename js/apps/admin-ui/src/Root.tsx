import { IamshieldProvider } from "@iamshield/iamshield-ui-shared";

import { App } from "./App";
import { environment } from "./environment";

export const Root = () => (
  <IamshieldProvider environment={environment}>
    <App />
  </IamshieldProvider>
);
