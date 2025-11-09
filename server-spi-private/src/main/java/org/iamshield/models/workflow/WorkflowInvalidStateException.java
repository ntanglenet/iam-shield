package org.iamshield.models.workflow;

import org.iamshield.models.ModelValidationException;

public class WorkflowInvalidStateException extends ModelValidationException {

    public WorkflowInvalidStateException(String message) {
        super(message);
    }
}
