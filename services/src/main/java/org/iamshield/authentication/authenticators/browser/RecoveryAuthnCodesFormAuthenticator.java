package org.iamshield.authentication.authenticators.browser;

import org.iamshield.authentication.AuthenticationFlowContext;
import org.iamshield.authentication.AuthenticationFlowError;
import org.iamshield.authentication.Authenticator;
import org.iamshield.authentication.CredentialValidator;
import org.iamshield.authentication.authenticators.util.AuthenticatorUtils;
import org.iamshield.common.util.ObjectUtil;
import org.iamshield.credential.CredentialModel;
import org.iamshield.credential.CredentialProvider;
import org.iamshield.credential.RecoveryAuthnCodesCredentialProvider;
import org.iamshield.credential.RecoveryAuthnCodesCredentialProviderFactory;
import org.iamshield.events.Details;
import org.iamshield.events.Errors;
import org.iamshield.forms.login.LoginFormsProvider;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.RealmModel;
import org.iamshield.models.UserCredentialModel;
import org.iamshield.models.UserModel;
import org.iamshield.models.credential.RecoveryAuthnCodesCredentialModel;
import org.iamshield.models.utils.RecoveryAuthnCodesUtils;
import org.iamshield.models.utils.FormMessage;
import org.iamshield.services.messages.Messages;
import org.iamshield.sessions.AuthenticationSessionModel;
import org.iamshield.storage.ReadOnlyException;

import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import java.util.Optional;

import static org.iamshield.services.validation.Validation.FIELD_USERNAME;

public class RecoveryAuthnCodesFormAuthenticator implements Authenticator, CredentialValidator<RecoveryAuthnCodesCredentialProvider> {

    public static final String GENERATED_RECOVERY_AUTHN_CODES_NOTE = "RecoveryAuthnCodes.generatedRecoveryAuthnCodes";
    public static final String GENERATED_AT_NOTE = "RecoveryAuthnCodes.generatedAt";

    public RecoveryAuthnCodesFormAuthenticator(IAMShieldSession keycloakSession) {
    }

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        context.challenge(createLoginForm(context, false, null, null));
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        context.getEvent().detail(Details.CREDENTIAL_TYPE, RecoveryAuthnCodesCredentialModel.TYPE)
                .user(context.getUser());
        if (isRecoveryAuthnCodeInputValid(context)) {
            context.success(RecoveryAuthnCodesCredentialModel.TYPE);
        }
    }

    private boolean isRecoveryAuthnCodeInputValid(AuthenticationFlowContext authnFlowContext) {
        boolean result = false;
        MultivaluedMap<String, String> formParamsMap = authnFlowContext.getHttpRequest().getDecodedFormParameters();
        String recoveryAuthnCodeUserInput = formParamsMap.getFirst(RecoveryAuthnCodesUtils.FIELD_RECOVERY_CODE_IN_BROWSER_FLOW);

        UserModel authenticatedUser = authnFlowContext.getUser();
        boolean disabledByBruteForce = isDisabledByBruteForce(authnFlowContext, authenticatedUser);
        if (ObjectUtil.isBlank(recoveryAuthnCodeUserInput)
                || "true".equals(authnFlowContext.getAuthenticationSession().getAuthNote(AbstractUsernameFormAuthenticator.SESSION_INVALID))) {
            // the brute force lock might be lifted in the meantime -> we need to clear the auth session note
            if (!disabledByBruteForce) {
                authnFlowContext.getAuthenticationSession().removeAuthNote(AbstractUsernameFormAuthenticator.SESSION_INVALID);
            } else {
                authnFlowContext.forceChallenge(createLoginForm(authnFlowContext, true,
                        RecoveryAuthnCodesUtils.RECOVERY_AUTHN_CODES_INPUT_DEFAULT_ERROR_MESSAGE,
                        RecoveryAuthnCodesUtils.FIELD_RECOVERY_CODE_IN_BROWSER_FLOW));
                return result;
            }
        }

        if (!disabledByBruteForce) {
            boolean isValid = authenticatedUser.credentialManager().isValid(
                    UserCredentialModel.buildFromBackupAuthnCode(recoveryAuthnCodeUserInput.replace("-", "")));
            if (!isValid) {
                Response responseChallenge = createLoginForm(authnFlowContext, true,
                        RecoveryAuthnCodesUtils.RECOVERY_AUTHN_CODES_INPUT_DEFAULT_ERROR_MESSAGE,
                        RecoveryAuthnCodesUtils.FIELD_RECOVERY_CODE_IN_BROWSER_FLOW);
                authnFlowContext.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, responseChallenge);
            } else {
                result = true;
                Optional<CredentialModel> optUserCredentialFound = RecoveryAuthnCodesUtils.getCredential(authenticatedUser);
                RecoveryAuthnCodesCredentialModel recoveryCodeCredentialModel = null;
                if (optUserCredentialFound.isPresent()) {
                    recoveryCodeCredentialModel = RecoveryAuthnCodesCredentialModel
                            .createFromCredentialModel(optUserCredentialFound.get());
                    if (recoveryCodeCredentialModel.allCodesUsed()) {
                        authenticatedUser.credentialManager().removeStoredCredentialById(
                                recoveryCodeCredentialModel.getId());
                    }
                }
                if (recoveryCodeCredentialModel == null || recoveryCodeCredentialModel.allCodesUsed()) {
                    addRequiredAction(authnFlowContext);
                }
            }
        }
        else {
            authnFlowContext.getAuthenticationSession().setAuthNote(AbstractUsernameFormAuthenticator.SESSION_INVALID, "true");
        }
        return result;
    }

    protected void addRequiredAction(AuthenticationFlowContext authnFlowContext) {
        try {
            authnFlowContext.getUser().addRequiredAction(UserModel.RequiredAction.CONFIGURE_RECOVERY_AUTHN_CODES);
        } catch (ReadOnlyException e) {
            // user is read-only, at least add the action to the auth session
            authnFlowContext.getAuthenticationSession().addRequiredAction(UserModel.RequiredAction.CONFIGURE_RECOVERY_AUTHN_CODES);
        }
    }

    protected boolean isDisabledByBruteForce(AuthenticationFlowContext authnFlowContext, UserModel authenticatedUser) {
        String bruteForceError;
        Response challengeResponse;
        bruteForceError = getDisabledByBruteForceEventError(authnFlowContext, authenticatedUser);
        if (bruteForceError == null) {
            return false;
        }
        authnFlowContext.getEvent().user(authenticatedUser);
        authnFlowContext.getEvent().error(bruteForceError);
        challengeResponse = createLoginForm(authnFlowContext, false, Messages.INVALID_USER, FIELD_USERNAME);
        authnFlowContext.forceChallenge(challengeResponse);
        return true;
    }

    protected String getDisabledByBruteForceEventError(AuthenticationFlowContext authnFlowContext, UserModel authenticatedUser) {
        return AuthenticatorUtils.getDisabledByBruteForceEventError(authnFlowContext, authenticatedUser);
    }

    private Response createLoginForm(AuthenticationFlowContext authnFlowContext, boolean withInvalidUserCredentialsError,
            String errorToRaise, String fieldError) {
        Response challengeResponse;
        LoginFormsProvider loginFormsProvider;
        if (withInvalidUserCredentialsError) {
            loginFormsProvider = authnFlowContext.form();
            authnFlowContext.getEvent().user(authnFlowContext.getUser());
            authnFlowContext.getEvent().error(Errors.INVALID_USER_CREDENTIALS);
            loginFormsProvider.addError(new FormMessage(fieldError, errorToRaise));
        } else {
            loginFormsProvider = authnFlowContext.form().setExecution(authnFlowContext.getExecution().getId());
            if (errorToRaise != null) {
                if (fieldError != null) {
                    loginFormsProvider.addError(new FormMessage(fieldError, errorToRaise));
                } else {
                    loginFormsProvider.setError(errorToRaise);
                }
            }
        }
        challengeResponse = loginFormsProvider.createLoginRecoveryAuthnCode();
        return challengeResponse;
    }

    @Override
    public boolean requiresUser() {
        return true;
    }

    @Override
    public boolean configuredFor(IAMShieldSession session, RealmModel realm, UserModel user) {
        return user.credentialManager().isConfiguredFor(RecoveryAuthnCodesCredentialModel.TYPE);
    }

    @Override
    public void setRequiredActions(IAMShieldSession session, RealmModel realm, UserModel user) {
        AuthenticationSessionModel authenticationSession = session.getContext().getAuthenticationSession();
        if (!authenticationSession.getRequiredActions().contains(UserModel.RequiredAction.CONFIGURE_RECOVERY_AUTHN_CODES.name())) {
            authenticationSession.addRequiredAction(UserModel.RequiredAction.CONFIGURE_RECOVERY_AUTHN_CODES.name());
        }
    }

    @Override
    public void close() {
    }

    @Override
    public RecoveryAuthnCodesCredentialProvider getCredentialProvider(IAMShieldSession session) {
        return (RecoveryAuthnCodesCredentialProvider)session.getProvider(CredentialProvider.class, RecoveryAuthnCodesCredentialProviderFactory.PROVIDER_ID);
    }

    @Override
    public String getType(IAMShieldSession session) {
        return RecoveryAuthnCodesCredentialModel.TYPE;
    }
}
