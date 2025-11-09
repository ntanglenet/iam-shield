package org.iamshield.authentication;

import org.iamshield.credential.CredentialProvider;
import org.iamshield.credential.CredentialTypeMetadata;
import org.iamshield.credential.CredentialTypeMetadataContext;
import org.iamshield.models.AuthenticationExecutionModel;
import org.iamshield.models.IAMShieldSession;

public class AuthenticationSelectionOption {

    private final AuthenticationExecutionModel authExec;
    private final CredentialTypeMetadata credentialTypeMetadata;

    public AuthenticationSelectionOption(IAMShieldSession session, AuthenticationExecutionModel authExec) {
        this.authExec = authExec;
        Authenticator authenticator = session.getProvider(Authenticator.class, authExec.getAuthenticator());
        if (authenticator instanceof CredentialValidator) {
            CredentialProvider credentialProvider = ((CredentialValidator) authenticator).getCredentialProvider(session);

            CredentialTypeMetadataContext ctx = CredentialTypeMetadataContext.builder()
                    .build(session);
            credentialTypeMetadata = credentialProvider.getCredentialTypeMetadata(ctx);
        } else {
            credentialTypeMetadata = null;
        }
    }


    public AuthenticationExecutionModel getAuthenticationExecution() {
        return authExec;
    }

    public String getAuthExecId(){
        return authExec.getId();
    }

    public String getDisplayName() {
        return credentialTypeMetadata == null ? authExec.getAuthenticator() + "-display-name" : credentialTypeMetadata.getDisplayName();
    }

    public String getHelpText() {
        return credentialTypeMetadata == null ? authExec.getAuthenticator() + "-help-text" : credentialTypeMetadata.getHelpText();
    }

    public String getIconCssClass() {
        // For now, we won't allow to retrieve "iconCssClass" from the AuthenticatorFactory. We will see in the future if we need
        // this capability for authenticator factories, which authenticators don't implement credentialProvider
        return credentialTypeMetadata == null ? CredentialTypeMetadata.DEFAULT_ICON_CSS_CLASS : credentialTypeMetadata.getIconCssClass();
    }


    @Override
    public String toString() {
        return " authSelection - " + authExec.getAuthenticator();
    }
}
