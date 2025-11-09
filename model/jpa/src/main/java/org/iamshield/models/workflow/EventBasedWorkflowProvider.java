package org.iamshield.models.workflow;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import org.iamshield.component.ComponentModel;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.IAMShieldSessionFactory;

public class EventBasedWorkflowProvider implements WorkflowProvider {

    private final IAMShieldSession session;
    private final ComponentModel model;

    public EventBasedWorkflowProvider(IAMShieldSession session, ComponentModel model) {
        this.session = session;
        this.model = model;
    }

    @Override
    public List<String> getEligibleResourcesForInitialStep() {
        return List.of();
    }

    @Override
    public boolean supports(ResourceType type) {
        return ResourceType.USERS.equals(type);
    }

    @Override
    public boolean activateOnEvent(WorkflowEvent event) {
        if (!supports(event.getResourceType())) {
            return false;
        }

        if (!isActivationEvent(event)) {
            return false;
        }

        return evaluate(event);
    }

    protected boolean isActivationEvent(WorkflowEvent event) {
        ResourceOperationType operation = event.getOperation();

        if (ResourceOperationType.AD_HOC.equals(operation)) {
            return true;
        }

        List<String> events = model.getConfig().getOrDefault("events", List.of());

        return events.contains(operation.name());
    }

    @Override
    public boolean deactivateOnEvent(WorkflowEvent event) {
        if (!supports(event.getResourceType())) {
            return false;
        }

        List<String> events = model.getConfig().getOrDefault("events", List.of());

        for (String activationEvent : events) {
            ResourceOperationType a = ResourceOperationType.valueOf(activationEvent);

            if (a.isDeactivationEvent(event.getEvent().getClass())) {
                return !evaluate(event);
            }
        }

        return false;
    }

    @Override
    public boolean resetOnEvent(WorkflowEvent event) {
        return isResetEvent(event) && evaluate(event);
    }

    protected boolean isResetEvent(WorkflowEvent event) {
        boolean resetEventEnabled = Boolean.parseBoolean(getModel().getConfig().getFirstOrDefault("reset-event-enabled", Boolean.FALSE.toString()));
        return resetEventEnabled && isActivationEvent(event);
    }

    @Override
    public void close() {

    }

    protected boolean evaluate(WorkflowEvent event) {
        List<String> conditions = getModel().getConfig().getOrDefault("conditions", List.of());

        for (String providerId : conditions) {
            WorkflowConditionProvider condition = resolveCondition(providerId);

            if (!condition.evaluate(event)) {
                return false;
            }
        }

        return true;
    }

    protected WorkflowConditionProvider resolveCondition(String providerId) {
        IAMShieldSessionFactory sessionFactory = session.getIAMShieldSessionFactory();
        WorkflowConditionProviderFactory<WorkflowConditionProvider> providerFactory = (WorkflowConditionProviderFactory<WorkflowConditionProvider>) sessionFactory.getProviderFactory(WorkflowConditionProvider.class, providerId);

        if (providerFactory == null) {
            throw new IllegalStateException("Could not find condition provider: " + providerId);
        }

        Map<String, List<String>> config = new HashMap<>();

        for (Entry<String, List<String>> configEntry : model.getConfig().entrySet()) {
            if (configEntry.getKey().startsWith(providerId)) {
                config.put(configEntry.getKey().substring(providerId.length() + 1), configEntry.getValue());
            }
        }

        WorkflowConditionProvider condition = providerFactory.create(session, config);

        if (condition == null) {
            throw new IllegalStateException("Factory " + providerFactory.getClass() + " returned a null provider");
        }

        return condition;
    }

    protected ComponentModel getModel() {
        return model;
    }

    protected IAMShieldSession getSession() {
        return session;
    }
}
