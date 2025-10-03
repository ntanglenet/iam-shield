package org.iamshield.models.workflow;

import org.jboss.logging.Logger;
import org.iamshield.models.IAMShieldContext;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.IAMShieldSessionFactory;
import org.iamshield.models.RealmModel;
import org.iamshield.models.utils.IAMShieldModelUtils;
import org.iamshield.timer.ScheduledTask;

/**
 * A {@link ScheduledTask} that runs all the scheduled steps for resources on a per-realm basis.
 */
final class WorkflowRunnerScheduledTask implements ScheduledTask {

    private final Logger logger = Logger.getLogger(WorkflowRunnerScheduledTask.class);

    private final IAMShieldSessionFactory sessionFactory;

    WorkflowRunnerScheduledTask(IAMShieldSessionFactory sessionFactory) {
        this.sessionFactory = sessionFactory;
    }

    @Override
    public void run(IAMShieldSession session) {
        // TODO: Depending on how many realms and the steps in use, this task can consume a lot of gears (e.g.: cpu, memory, and network)
        // we need a smarter mechanism that process realms in batches with some window interval
        session.realms().getRealmsStream().map(RealmModel::getId).forEach(this::runScheduledTasksOnRealm);
    }

    private void runScheduledTasksOnRealm(String id) {
        IAMShieldModelUtils.runJobInTransaction(sessionFactory, (IAMShieldSession session) -> {
            try {
                IAMShieldContext context = session.getContext();
                RealmModel realm = session.realms().getRealm(id);

                context.setRealm(realm);
                new WorkflowsManager(session).runScheduledSteps();

                sessionFactory.publish(new WorkflowStepRunnerSuccessEvent(session));
            } catch (Exception e) {
                logger.errorf(e, "Failed to run workflow steps on realm with id '%s'", id);
            }
        });
    }

    @Override
    public String getTaskName() {
        return "workflow-runner-task";
    }
}
