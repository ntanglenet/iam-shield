package org.iamshield.broker.provider;

import org.jboss.logging.Logger;
import org.iamshield.models.IdentityProviderMapperModel;
import org.iamshield.models.IdentityProviderMapperSyncMode;
import org.iamshield.models.IdentityProviderSyncMode;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.RealmModel;
import org.iamshield.models.UserModel;

public final class IdentityProviderMapperSyncModeDelegate {

    protected static final Logger logger = Logger.getLogger(IdentityProviderMapperSyncModeDelegate.class);

    public static void delegateUpdateBrokeredUser(IAMShieldSession session, RealmModel realm, UserModel user, IdentityProviderMapperModel mapperModel, BrokeredIdentityContext context, IdentityProviderMapper mapper) {
        IdentityProviderSyncMode effectiveSyncMode = combineIdpAndMapperSyncMode(context.getIdpConfig().getSyncMode(), mapperModel.getSyncMode());

        if (!mapper.supportsSyncMode(effectiveSyncMode)) {
            logger.warnf("The mapper %s does not explicitly support sync mode %s. Please ensure that the SPI supports the sync mode correctly and update it to reflect this.", mapper.getDisplayType(), effectiveSyncMode);
        }

        if (effectiveSyncMode == IdentityProviderSyncMode.LEGACY) {
            mapper.updateBrokeredUserLegacy(session, realm, user, mapperModel, context);
        } else if (effectiveSyncMode == IdentityProviderSyncMode.FORCE) {
            mapper.updateBrokeredUser(session, realm, user, mapperModel, context);
        }
    }

    public static IdentityProviderSyncMode combineIdpAndMapperSyncMode(IdentityProviderSyncMode syncMode, IdentityProviderMapperSyncMode mapperSyncMode) {
        return IdentityProviderMapperSyncMode.INHERIT.equals(mapperSyncMode) ? syncMode : IdentityProviderSyncMode.valueOf(mapperSyncMode.toString());
    }
}
