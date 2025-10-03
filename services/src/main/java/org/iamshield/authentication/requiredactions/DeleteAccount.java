/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.iamshield.authentication.requiredactions;

import jakarta.ws.rs.ForbiddenException;
import org.jboss.logging.Logger;
import org.iamshield.Config;
import org.iamshield.authentication.AuthenticationProcessor;
import org.iamshield.authentication.InitiatedActionSupport;
import org.iamshield.authentication.RequiredActionContext;
import org.iamshield.authentication.RequiredActionFactory;
import org.iamshield.authentication.RequiredActionProvider;
import org.iamshield.events.Details;
import org.iamshield.events.Errors;
import org.iamshield.events.EventBuilder;
import org.iamshield.events.EventType;
import org.iamshield.models.AccountRoles;
import org.iamshield.models.Constants;
import org.iamshield.models.IAMShieldContext;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.IAMShieldSessionFactory;
import org.iamshield.models.RealmModel;
import org.iamshield.models.RoleModel;
import org.iamshield.models.UserManager;
import org.iamshield.models.UserModel;
import org.iamshield.provider.ProviderConfigProperty;
import org.iamshield.services.managers.AuthenticationManager;
import org.iamshield.services.managers.AuthenticationSessionManager;
import org.iamshield.services.messages.Messages;
import org.iamshield.sessions.AuthenticationSessionModel;

import java.util.Collections;
import java.util.List;
import java.util.Objects;
public class DeleteAccount implements RequiredActionProvider, RequiredActionFactory {

  public static final String PROVIDER_ID = "delete_account";

  private static final String TRIGGERED_FROM_AIA = "triggered_from_aia";

  private static final Logger logger = Logger.getLogger(DeleteAccount.class);

    @Override
  public String getDisplayText() {
    return "Delete Account";
  }

  @Override
  public void evaluateTriggers(RequiredActionContext context) {

  }

  @Override
  public void requiredActionChallenge(RequiredActionContext context) {
      if (!clientHasDeleteAccountRole(context)) {
        context.challenge(context.form().setError(Messages.DELETE_ACCOUNT_LACK_PRIVILEDGES).createForm("error.ftl"));
        return;
      }

      context.challenge(context.form().setAttribute(TRIGGERED_FROM_AIA, isCurrentActionTriggeredFromAIA(context)).createForm("delete-account-confirm.ftl"));
  }


  @Override
  public void processAction(RequiredActionContext context) {
    IAMShieldSession session = context.getSession();
    EventBuilder eventBuilder = context.getEvent();
    IAMShieldContext keycloakContext = session.getContext();
    RealmModel realm = keycloakContext.getRealm();
    UserModel user = keycloakContext.getAuthenticationSession().getAuthenticatedUser();

    try {
      if(!clientHasDeleteAccountRole(context)) {
        throw new ForbiddenException();
      }
      boolean removed = new UserManager(session).removeUser(realm, user);

      if (removed) {
        eventBuilder.event(EventType.DELETE_ACCOUNT)
            .client(keycloakContext.getClient())
            .user(user)
            .detail(Details.USERNAME, user.getUsername())
            .success();

        removeAuthenticationSession(context, session);

        context.challenge(context.form()
            .setAttribute("messageHeader", "")
            .setInfo("userDeletedSuccessfully")
            .createForm("info.ftl"));
      } else {
        eventBuilder.event(EventType.DELETE_ACCOUNT)
            .client(keycloakContext.getClient())
            .user(user)
            .detail(Details.USERNAME, user.getUsername())
            .error("User could not be deleted");

        cleanSession(context, RequiredActionContext.KcActionStatus.ERROR);
        context.failure();
      }

    } catch (ForbiddenException forbidden) {
      logger.error("account client does not have the required roles for user deletion");
      eventBuilder.event(EventType.DELETE_ACCOUNT_ERROR)
          .client(keycloakContext.getClient())
          .user(keycloakContext.getAuthenticationSession().getAuthenticatedUser())
          .detail(Details.REASON, "does not have the required roles for user deletion")
          .error(Errors.USER_DELETE_ERROR);
      //deletingAccountForbidden
      context.challenge(context.form().setAttribute(TRIGGERED_FROM_AIA, isCurrentActionTriggeredFromAIA(context)).setError(Messages.DELETE_ACCOUNT_LACK_PRIVILEDGES).createForm("delete-account-confirm.ftl"));
    } catch (Exception exception) {
      logger.error("unexpected error happened during account deletion", exception);
      eventBuilder.event(EventType.DELETE_ACCOUNT_ERROR)
          .client(keycloakContext.getClient())
          .user(keycloakContext.getAuthenticationSession().getAuthenticatedUser())
          .detail(Details.REASON, exception.getMessage())
          .error(Errors.USER_DELETE_ERROR);
      context.challenge(context.form().setError(Messages.DELETE_ACCOUNT_ERROR).createForm("delete-account-confirm.ftl"));
    }
  }

  private void cleanSession(RequiredActionContext context, RequiredActionContext.KcActionStatus status) {
    context.getAuthenticationSession().removeRequiredAction(PROVIDER_ID);
    context.getAuthenticationSession().removeAuthNote(AuthenticationProcessor.CURRENT_AUTHENTICATION_EXECUTION);
    AuthenticationManager.setKcActionStatus(PROVIDER_ID, status, context.getAuthenticationSession());
  }

  private boolean clientHasDeleteAccountRole(RequiredActionContext context) {
    RoleModel deleteAccountRole = context.getRealm().getClientByClientId(Constants.ACCOUNT_MANAGEMENT_CLIENT_ID).getRole(AccountRoles.DELETE_ACCOUNT);
    return deleteAccountRole != null && context.getUser().hasRole(deleteAccountRole);
  }

  private boolean isCurrentActionTriggeredFromAIA(RequiredActionContext context) {
    return Objects.equals(context.getAuthenticationSession().getClientNote(Constants.KC_ACTION), PROVIDER_ID);
  }

  @Override
  public RequiredActionProvider create(IAMShieldSession session) {
    return this;
  }

  @Override
  public void init(Config.Scope config) {

  }

  @Override
  public void postInit(IAMShieldSessionFactory factory) {

  }

  @Override
  public void close() {

  }

  @Override
  public String getId() {
    return PROVIDER_ID;
  }

  @Override
  public InitiatedActionSupport initiatedActionSupport() {
    return InitiatedActionSupport.SUPPORTED;
  }

  @Override
  public boolean isOneTimeAction() {
    return true;
  }

  @Override
  public int getMaxAuthAge(IAMShieldSession session) {
    return 0;
  }

  @Override
  public List<ProviderConfigProperty> getConfigMetadata() {
      return Collections.emptyList();
  }

  private void removeAuthenticationSession(RequiredActionContext context, IAMShieldSession session) {
    AuthenticationSessionModel authSession = context.getAuthenticationSession();
    new AuthenticationSessionManager(session).removeAuthenticationSession(authSession.getRealm(), authSession, true);
  }
}
