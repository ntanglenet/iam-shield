package org.iamshield.services.resources.account;

import java.io.IOException;
import org.iamshield.Config.Scope;
import org.iamshield.models.ClientModel;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.IAMShieldSessionFactory;
import org.iamshield.models.RealmModel;
import org.iamshield.services.resource.AccountResourceProvider;
import org.iamshield.services.resource.AccountResourceProviderFactory;
import org.iamshield.theme.Theme;
import jakarta.ws.rs.InternalServerErrorException;
import jakarta.ws.rs.NotFoundException;
import org.iamshield.models.Constants;

/**
 * Provides the {@code default} {@link AccountConsole} implementation backed by the
 * {@code account} management client.
 */
public class AccountConsoleFactory implements AccountResourceProviderFactory {

  @Override
  public String getId() {
    return "default";
  }

  @Override
  public AccountResourceProvider create(IAMShieldSession session) {
    RealmModel realm = session.getContext().getRealm();
    ClientModel client = getAccountManagementClient(realm);
    Theme theme = getTheme(session);
    return createAccountConsole(session, client, theme);
  }

  protected AccountConsole createAccountConsole(IAMShieldSession session, ClientModel client, Theme theme) {
    return new AccountConsole(session, client, theme);
  }

  @Override
  public void init(Scope config) {}

  @Override
  public void postInit(IAMShieldSessionFactory factory) {}

  @Override
  public void close() {}

  protected Theme getTheme(IAMShieldSession session) {
    try {
      return session.theme().getTheme(Theme.Type.ACCOUNT);
    } catch (IOException e) {
      throw new InternalServerErrorException(e);
    }
  }

  protected  ClientModel getAccountManagementClient(RealmModel realm) {
    ClientModel client = realm.getClientByClientId(Constants.ACCOUNT_MANAGEMENT_CLIENT_ID);
    if (client == null || !client.isEnabled()) {
      throw new NotFoundException("account management not enabled");
    }
    return client;
  }
}
