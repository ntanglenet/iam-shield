package org.iamshield.storage.datastore;

import org.iamshield.provider.InvalidationHandler;

public enum PeriodicEventInvalidation implements InvalidationHandler.InvalidableObjectType {
    JPA_EVENT_STORE,
}
