package org.iamshield.models.workflow;

import org.iamshield.models.IAMShieldSession;
import org.iamshield.provider.ProviderEvent;

public record WorkflowStepRunnerSuccessEvent(IAMShieldSession session) implements ProviderEvent {
}
