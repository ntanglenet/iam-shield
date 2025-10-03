package org.iamshield.models.workflow;

import org.jboss.logging.Logger;
import org.iamshield.component.ComponentModel;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.RealmModel;
import org.iamshield.models.UserModel;

import java.util.List;

public class AddRequiredActionStepProvider implements WorkflowStepProvider {

    public static String REQUIRED_ACTION_KEY = "action";

    private final IAMShieldSession session;
    private final ComponentModel stepModel;
    private final Logger log = Logger.getLogger(AddRequiredActionStepProvider.class);

    public AddRequiredActionStepProvider(IAMShieldSession session, ComponentModel model) {
        this.session = session;
        this.stepModel = model;
    }

    @Override
    public void run(List<String> userIds) {
        RealmModel realm = session.getContext().getRealm();

        for (String id : userIds) {
            UserModel user = session.users().getUserById(realm, id);

            if (user != null) {
                try {
                    UserModel.RequiredAction action = UserModel.RequiredAction.valueOf(stepModel.getConfig().getFirst(REQUIRED_ACTION_KEY));
                    log.debugv("Adding required action {0} to user {1})", action, user.getId());
                    user.addRequiredAction(action);
                } catch (IllegalArgumentException e) {
                    log.warnv("Invalid required action {0} configured in AddRequiredActionProvider", stepModel.getConfig().getFirst(REQUIRED_ACTION_KEY));
                }
            }
        }
    }

    @Override
    public void close() {
    }
}
