import { Spinner } from "@patternfly/react-core";
import Keycloak from "keycloak-js";
import {
  PropsWithChildren,
  createContext,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import { AlertProvider } from "../alerts/Alerts";
import { ErrorPage } from "./ErrorPage";
import { Help } from "./HelpContext";
import { BaseEnvironment } from "./environment";

export type IamshieldContext<T extends BaseEnvironment = BaseEnvironment> =
  IamshieldContextProps<T> & {
    Iamshield: Keycloak;
  };

const createIamshieldEnvContext = <T extends BaseEnvironment>() =>
  createContext<IamshieldContext<T> | undefined>(undefined);

let IamshieldEnvContext: any;

export const useEnvironment = <
  T extends BaseEnvironment = BaseEnvironment,
>() => {
  const context = useContext<IamshieldContext<T>>(IamshieldEnvContext);
  if (!context)
    throw Error(
      "no environment provider in the hierarchy make sure to add the provider",
    );
  return context;
};

interface IamshieldContextProps<T extends BaseEnvironment> {
  environment: T;
}

export const IamshieldProvider = <T extends BaseEnvironment>({
  environment,
  children,
}: PropsWithChildren<IamshieldContextProps<T>>) => {
  IamshieldEnvContext = createIamshieldEnvContext<T>();
  const calledOnce = useRef(false);
  const [init, setInit] = useState(false);
  const [error, setError] = useState<unknown>();
  const Iamshield = useMemo(() => {
    const Iamshield = new Keycloak({
      url: environment.serverBaseUrl,
      realm: environment.realm,
      clientId: environment.clientId,
    });

    Iamshield.onAuthLogout = () => Iamshield.login();

    return Iamshield;
  }, [environment]);

  useEffect(() => {
    // only needed in dev mode
    if (calledOnce.current) {
      return;
    }

    const init = () =>
      Iamshield.init({
        onLoad: "login-required",
        pkceMethod: "S256",
        responseMode: "query",
        scope: environment.scope,
      });

    init()
      .then(() => setInit(true))
      .catch((error) => setError(error));

    calledOnce.current = true;
  }, [Iamshield]);

  if (error) {
    return <ErrorPage error={error} />;
  }

  if (!init) {
    return <Spinner />;
  }

  return (
    <IamshieldEnvContext.Provider value={{ environment, Iamshield }}>
      <AlertProvider>
        <Help>{children}</Help>
      </AlertProvider>
    </IamshieldEnvContext.Provider>
  );
};
