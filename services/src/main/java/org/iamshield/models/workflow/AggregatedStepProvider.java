package org.iamshield.models.workflow;

import java.util.List;

import org.jboss.logging.Logger;
import org.iamshield.component.ComponentModel;
import org.iamshield.models.IAMShieldSession;

public class AggregatedStepProvider implements WorkflowStepProvider {

    private final IAMShieldSession session;
    private final ComponentModel model;
    private final Logger log = Logger.getLogger(AggregatedStepProvider.class);

    public AggregatedStepProvider(IAMShieldSession session, ComponentModel model) {
        this.session = session;
        this.model = model;
    }

    @Override
    public void close() {
    }

    @Override
    public void run(List<String> userIds) {
        List<WorkflowStepProvider> steps = getSteps();

        for (String userId : userIds) {
            for (WorkflowStepProvider step : steps) {
                try {
                    step.run(List.of(userId));
                } catch (Exception e) {
                    log.errorf(e, "Failed to execute step %s for user %s", model.getProviderId(), userId);
                }
            }
        }
    }

    private List<WorkflowStepProvider> getSteps() {
        WorkflowsManager manager = new WorkflowsManager(session);

        return manager.getStepById(model.getId())
                .getSteps().stream()
                .map(manager::getStepProvider)
                .toList();
    }
}
