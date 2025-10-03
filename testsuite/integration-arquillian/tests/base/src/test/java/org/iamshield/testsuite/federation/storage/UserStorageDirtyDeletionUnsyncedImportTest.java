package org.iamshield.testsuite.federation.storage;

import org.iamshield.representations.idm.ComponentRepresentation;
import org.iamshield.storage.UserStorageProvider.EditMode;

/**
 *
 * @author hmlnarik
 */
public final class UserStorageDirtyDeletionUnsyncedImportTest extends AbstractUserStorageDirtyDeletionTest {

    @Override
    protected ComponentRepresentation getFederationProvider() {
        return getFederationProvider(EditMode.UNSYNCED, true);
    }

}
