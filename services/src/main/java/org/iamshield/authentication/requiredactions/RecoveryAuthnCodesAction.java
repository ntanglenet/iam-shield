package org.iamshield.authentication.requiredactions;

import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import org.iamshield.Config;
import org.iamshield.authentication.AuthenticatorUtil;
import org.iamshield.authentication.CredentialRegistrator;
import org.iamshield.authentication.InitiatedActionSupport;
import org.iamshield.authentication.RequiredActionContext;
import org.iamshield.authentication.RequiredActionFactory;
import org.iamshield.authentication.RequiredActionProvider;
import org.iamshield.authentication.authenticators.browser.RecoveryAuthnCodesFormAuthenticator;
import org.iamshield.common.Profile;
import org.iamshield.events.Details;
import org.iamshield.events.EventBuilder;
import org.iamshield.events.EventType;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.IAMShieldSessionFactory;
import org.iamshield.models.RealmModel;
import org.iamshield.models.RequiredActionConfigModel;
import org.iamshield.models.UserModel;
import org.iamshield.models.credential.RecoveryAuthnCodesCredentialModel;
import org.iamshield.provider.EnvironmentDependentProviderFactory;
import org.iamshield.provider.ProviderConfigProperty;
import org.iamshield.provider.ProviderConfigurationBuilder;
import org.iamshield.sessions.AuthenticationSessionModel;
import org.iamshield.userprofile.ValidationException;
import org.iamshield.validate.ValidationError;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Stream;

import static org.iamshield.utils.CredentialHelper.createRecoveryCodesCredential;

public class RecoveryAuthnCodesAction implements RequiredActionProvider, RequiredActionFactory, EnvironmentDependentProviderFactory, CredentialRegistrator {

    private static final String FIELD_GENERATED_RECOVERY_AUTHN_CODES_HIDDEN = "generatedRecoveryAuthnCodes";
    private static final String FIELD_GENERATED_AT_HIDDEN = "generatedAt";
    private static final String FIELD_USER_LABEL_HIDDEN = "userLabel";
    public static final String PROVIDER_ID = UserModel.RequiredAction.CONFIGURE_RECOVERY_AUTHN_CODES.name();
    private static final RecoveryAuthnCodesAction INSTANCE = new RecoveryAuthnCodesAction();

    private static final List<ProviderConfigProperty> CONFIG_PROPERTIES;

    public static final String WARNING_THRESHOLD = "warning_threshold";

    public static final int RECOVERY_CODES_WARNING_THRESHOLD_DEFAULT = 4;

    static {
        List<ProviderConfigProperty> properties = ProviderConfigurationBuilder.create() //
                .property() //
                .name(WARNING_THRESHOLD) //
                .label("Warning Threshold") //
                .helpText("When user has smaller amount of remaining recovery codes on his account than the value configured here, account console will show warning to the user, which will recommend him to setup new set of recovery codes.")
                .type(ProviderConfigProperty.INTEGER_TYPE) //
                .defaultValue(RECOVERY_CODES_WARNING_THRESHOLD_DEFAULT) //
                .add() //
                .build();

        CONFIG_PROPERTIES = properties;
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getCredentialType(IAMShieldSession session, AuthenticationSessionModel authenticationSession) {
        return RecoveryAuthnCodesCredentialModel.TYPE;
    }

    @Override
    public String getDisplayText() {
        return "Recovery Authentication Codes";
    }

    @Override
    public RequiredActionProvider create(IAMShieldSession session) {
        return INSTANCE;
    }

    @Override
    public void init(Config.Scope config) {
    }

    @Override
    public void postInit(IAMShieldSessionFactory factory) {
    }

    @Override
    public boolean isOneTimeAction() {
        return true;
    }

    @Override
    public InitiatedActionSupport initiatedActionSupport() {
        return InitiatedActionSupport.SUPPORTED;
    }

    @Override
    public void evaluateTriggers(RequiredActionContext context) {
    }

    @Override
    public void requiredActionChallenge(RequiredActionContext context) {
        Response challenge = context.form().createResponse(UserModel.RequiredAction.CONFIGURE_RECOVERY_AUTHN_CODES);
        context.challenge(challenge);
    }

    @Override
    public void processAction(RequiredActionContext reqActionContext) {
        EventBuilder event = reqActionContext.getEvent();
        event.event(EventType.UPDATE_CREDENTIAL);
        MultivaluedMap<String, String> httpReqParamsMap;

        event.detail(Details.CREDENTIAL_TYPE, RecoveryAuthnCodesCredentialModel.TYPE);

        httpReqParamsMap = reqActionContext.getHttpRequest().getDecodedFormParameters();
        final String generatedCodesString = httpReqParamsMap.getFirst(FIELD_GENERATED_RECOVERY_AUTHN_CODES_HIDDEN);
        final String generatedAtTimeString = httpReqParamsMap.getFirst(FIELD_GENERATED_AT_HIDDEN);
        final String generatedUserLabel = httpReqParamsMap.getFirst(FIELD_USER_LABEL_HIDDEN);

        if (!generatedAtTimeString.equals(reqActionContext.getAuthenticationSession().getAuthNote(RecoveryAuthnCodesFormAuthenticator.GENERATED_AT_NOTE))
                || !generatedCodesString.equals(reqActionContext.getAuthenticationSession().getAuthNote(RecoveryAuthnCodesFormAuthenticator.GENERATED_RECOVERY_AUTHN_CODES_NOTE))) {
            // authn codes have been tampered, sent them again
            requiredActionChallenge(reqActionContext);
            return;
        }

        reqActionContext.getAuthenticationSession().removeAuthNote(RecoveryAuthnCodesFormAuthenticator.GENERATED_AT_NOTE);
        reqActionContext.getAuthenticationSession().removeAuthNote(RecoveryAuthnCodesFormAuthenticator.GENERATED_RECOVERY_AUTHN_CODES_NOTE);

        List<String> generatedCodes = Arrays.asList(generatedCodesString.split(","));
        RecoveryAuthnCodesCredentialModel credentialModel = createFromValues(generatedCodes, Long.valueOf(generatedAtTimeString), generatedUserLabel);

        if ("on".equals(httpReqParamsMap.getFirst("logout-sessions"))) {
            AuthenticatorUtil.logoutOtherSessions(reqActionContext);
        }

        createRecoveryCodesCredential(reqActionContext.getSession(), reqActionContext.getRealm(), reqActionContext.getUser(), credentialModel, generatedCodes);

        reqActionContext.success();
    }

    protected RecoveryAuthnCodesCredentialModel createFromValues(List<String> generatedCodes, Long generatedAtTime, String generatedUserLabel) {
        return RecoveryAuthnCodesCredentialModel.createFromValues(generatedCodes,
                generatedAtTime, generatedUserLabel);
    }

    @Override
    public void close() {
    }

    @Override
    public boolean isSupported(Config.Scope config) {
        return Profile.isFeatureEnabled(Profile.Feature.RECOVERY_CODES);
    }

    @Override
    public List<ProviderConfigProperty> getConfigMetadata() {
        return Stream.concat(
                List.copyOf(CONFIG_PROPERTIES).stream(),
                RequiredActionFactory.super.getConfigMetadata().stream()
        ).toList();
    }

    @Override
    public void validateConfig(IAMShieldSession session, RealmModel realm, RequiredActionConfigModel model) {
        RequiredActionFactory.super.validateConfig(session, realm, model);

        int parsedMaxAuthAge;
        try {
            parsedMaxAuthAge = parseWarningThreshold(model);
        } catch (Exception ex) {
            throw new ValidationException(new ValidationError(getId(), WARNING_THRESHOLD, "error-invalid-value"));
        }

        if (parsedMaxAuthAge < 0) {
            throw new ValidationException(new ValidationError(getId(), WARNING_THRESHOLD, "error-number-out-of-range-too-small", 0));
        }
    }

    private int parseWarningThreshold(RequiredActionConfigModel model) throws NumberFormatException {
        return Integer.parseInt(model.getConfigValue(WARNING_THRESHOLD));
    }
}
