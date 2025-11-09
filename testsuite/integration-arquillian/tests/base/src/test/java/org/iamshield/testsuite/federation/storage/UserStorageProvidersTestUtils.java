package org.iamshield.testsuite.federation.storage;

import org.jboss.logging.Logger;
import org.iamshield.common.util.reflections.Types;
import org.iamshield.component.ComponentModel;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.StorageProviderRealmModel;
import org.iamshield.models.ModelException;
import org.iamshield.models.RealmModel;
import org.iamshield.storage.UserStorageProvider;
import org.iamshield.storage.UserStorageProviderFactory;
import org.iamshield.storage.UserStorageProviderModel;

import java.util.stream.Stream;

public class UserStorageProvidersTestUtils {

    private static final Logger logger = Logger.getLogger(UserStorageProvidersTestUtils.class);


    public static boolean isStorageProviderEnabled(RealmModel realm, String providerId) {
        UserStorageProviderModel model = getStorageProviderModel(realm, providerId);
        return model.isEnabled();
    }

    private static UserStorageProviderFactory getUserStorageProviderFactory(UserStorageProviderModel model, IAMShieldSession session) {
        return (UserStorageProviderFactory) session.getIAMShieldSessionFactory()
                .getProviderFactory(UserStorageProvider.class, model.getProviderId());
    }

    public static <T> Stream<T> getEnabledStorageProviders(IAMShieldSession session, RealmModel realm, Class<T> type) {
        return getStorageProviders(realm, session, type)
                .filter(UserStorageProviderModel::isEnabled)
                .map(model -> type.cast(getStorageProviderInstance(session, model, getUserStorageProviderFactory(model, session))));
    }

    public static UserStorageProvider getStorageProviderInstance(IAMShieldSession session, UserStorageProviderModel model, UserStorageProviderFactory factory) {
        UserStorageProvider instance = (UserStorageProvider)session.getAttribute(model.getId());
        if (instance != null) return instance;
        instance = factory.create(session, model);
        if (instance == null) {
            throw new IllegalStateException("UserStorageProvideFactory (of type " + factory.getClass().getName() + ") produced a null instance");
        }
        session.enlistForClose(instance);
        session.setAttribute(model.getId(), instance);
        return instance;
    }

    public static <T> Stream<UserStorageProviderModel> getStorageProviders(RealmModel realm, IAMShieldSession session, Class<T> type) {
        return ((StorageProviderRealmModel) realm).getUserStorageProvidersStream()
                .filter(model -> {
                    UserStorageProviderFactory factory = getUserStorageProviderFactory(model, session);
                    if (factory == null) {
                        logger.warnv("Configured UserStorageProvider {0} of provider id {1} does not exist in realm {2}",
                                model.getName(), model.getProviderId(), realm.getName());
                        return false;
                    } else {
                        return Types.supports(type, factory, UserStorageProviderFactory.class);
                    }
                });
    }

    public static UserStorageProvider getStorageProvider(IAMShieldSession session, RealmModel realm, String componentId) {
        ComponentModel model = realm.getComponent(componentId);
        if (model == null) return null;
        UserStorageProviderModel storageModel = new UserStorageProviderModel(model);
        UserStorageProviderFactory factory = (UserStorageProviderFactory)session.getIAMShieldSessionFactory().getProviderFactory(UserStorageProvider.class, model.getProviderId());
        if (factory == null) {
            throw new ModelException("Could not find UserStorageProviderFactory for: " + model.getProviderId());
        }
        return getStorageProviderInstance(session, storageModel, factory);
    }

    public static <T> Stream<T> getStorageProviders(IAMShieldSession session, RealmModel realm, Class<T> type) {
        return getStorageProviders(realm, session, type)
                .map(model -> type.cast(getStorageProviderInstance(session, model, getUserStorageProviderFactory(model, session))));
    }

    public static UserStorageProviderModel getStorageProviderModel(RealmModel realm, String componentId) {
        ComponentModel model = realm.getComponent(componentId);
        if (model == null) return null;
        return new UserStorageProviderModel(model);
    }

}
