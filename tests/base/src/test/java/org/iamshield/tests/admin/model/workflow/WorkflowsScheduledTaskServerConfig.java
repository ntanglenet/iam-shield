package org.iamshield.tests.admin.model.workflow;

import org.iamshield.models.workflow.WorkflowsEventListenerFactory;
import org.iamshield.testframework.server.IAMShieldServerConfigBuilder;

public class WorkflowsScheduledTaskServerConfig extends WorkflowsServerConfig {

    @Override
    public IAMShieldServerConfigBuilder configure(IAMShieldServerConfigBuilder config) {
        return super.configure(config)
                .option("spi-events-listener--" + WorkflowsEventListenerFactory.ID + "--step-runner-task-interval", "1000");
    }
}
