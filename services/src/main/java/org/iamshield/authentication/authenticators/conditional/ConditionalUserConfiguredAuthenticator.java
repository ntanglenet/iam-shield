package org.iamshield.authentication.authenticators.conditional;

import java.util.LinkedList;
import java.util.List;
import java.util.Objects;

import org.iamshield.authentication.AuthenticationFlowContext;
import org.iamshield.authentication.Authenticator;
import org.iamshield.authentication.AuthenticatorFactory;
import org.iamshield.models.AuthenticationExecutionModel;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.RealmModel;
import org.iamshield.models.UserModel;

public class ConditionalUserConfiguredAuthenticator implements ConditionalAuthenticator {
    public static final ConditionalUserConfiguredAuthenticator SINGLETON = new ConditionalUserConfiguredAuthenticator();

    @Override
    public boolean matchCondition(AuthenticationFlowContext context) {
        return matchConditionInFlow(context, context.getExecution().getParentFlow());
    }

    private boolean matchConditionInFlow(AuthenticationFlowContext context, String flowId) {
        List<AuthenticationExecutionModel> requiredExecutions = new LinkedList<>();
        List<AuthenticationExecutionModel> alternativeExecutions = new LinkedList<>();
        context.getRealm().getAuthenticationExecutionsStream(flowId)
                //Check if the execution's authenticator is a conditional authenticator, as they must not be evaluated here.
                .filter(e -> !isConditionalExecution(context, e))
                .filter(e -> !Objects.equals(context.getExecution().getId(), e.getId()) && !e.isAuthenticatorFlow())
                .forEachOrdered(e -> {
                    if (e.isRequired()) {
                        requiredExecutions.add(e);
                    } else if (e.isAlternative()) {
                        alternativeExecutions.add(e);
                    }
                });
        if (!requiredExecutions.isEmpty()) {
            return requiredExecutions.stream().allMatch(e -> isConfiguredFor(e, context));
        } else  if (!alternativeExecutions.isEmpty()) {
            return alternativeExecutions.stream().anyMatch(e -> isConfiguredFor(e, context));
        }
        return true;
    }

    private boolean isConditionalExecution(AuthenticationFlowContext context, AuthenticationExecutionModel e) {
        AuthenticatorFactory factory = (AuthenticatorFactory) context.getSession().getIAMShieldSessionFactory()
                .getProviderFactory(Authenticator.class, e.getAuthenticator());
        if (factory != null) {
            Authenticator auth = factory.create(context.getSession());
            return (auth instanceof ConditionalAuthenticator);
        }
        return false;
    }

    private boolean isConfiguredFor(AuthenticationExecutionModel model, AuthenticationFlowContext context) {
        if (model.isAuthenticatorFlow()) {
            return matchConditionInFlow(context, model.getId());
        }
        AuthenticatorFactory factory = (AuthenticatorFactory) context.getSession().getIAMShieldSessionFactory().getProviderFactory(Authenticator.class, model.getAuthenticator());
        Authenticator authenticator = factory.create(context.getSession());
        return authenticator.configuredFor(context.getSession(), context.getRealm(), context.getUser());
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        // Not used
    }

    @Override
    public boolean requiresUser() {
        return true;
    }

    @Override
    public void setRequiredActions(IAMShieldSession session, RealmModel realm, UserModel user) {
        // Not used
    }

    @Override
    public void close() {
        // Does nothing
    }
}
