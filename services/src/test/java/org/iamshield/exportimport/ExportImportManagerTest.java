package org.iamshield.exportimport;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.io.IOException;

import org.junit.After;
import org.junit.Test;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.provider.Provider;
import org.iamshield.services.DefaultIAMShieldContext;
import org.iamshield.services.DefaultIAMShieldSession;
import org.iamshield.services.DefaultIAMShieldSessionFactory;

public class ExportImportManagerTest {

    @After
    public void reset() {
        ExportImportConfig.reset();
    }

    @Test
    public void testImportOnStartup() {
        ExportImportConfig.setDir("/some/dir");
        new ExportImportManager(new DefaultIAMShieldSession(new DefaultIAMShieldSessionFactory() {

            @Override
            public IAMShieldSession create() {
                return null;
            }
        }) {

            @Override
            protected DefaultIAMShieldContext createIAMShieldContext(IAMShieldSession session) {
                return null;
            }

        });
        assertEquals(ExportImportConfig.ACTION_IMPORT, ExportImportConfig.getAction());
        assertEquals(Strategy.IGNORE_EXISTING.toString(), ExportImportConfig.getStrategy());
        assertTrue(ExportImportConfig.isReplacePlaceholders());
    }

    @Test
    public void testImport() {
        ExportImportConfig.setAction(ExportImportConfig.ACTION_IMPORT);
        new ExportImportManager(new DefaultIAMShieldSession(null) {

            @Override
            protected DefaultIAMShieldContext createIAMShieldContext(IAMShieldSession session) {
                return null;
            }

            @Override
            public <T extends Provider> T getProvider(Class<T> clazz, String id) {
                return (T) new ImportProvider() {

                    @Override
                    public void close() {

                    }

                    @Override
                    public boolean isMasterRealmExported() throws IOException {
                        return false;
                    }

                    @Override
                    public void importModel() throws IOException {

                    }
                };
            }

        });
        assertEquals(ExportImportConfig.ACTION_IMPORT, ExportImportConfig.getAction());
        assertNull(ExportImportConfig.getStrategy());
        // we're now setting this in the Quarkus logic, it's left as false in the ExportImportManager
        // for arquillian, or other legacy usage
        assertFalse(ExportImportConfig.isReplacePlaceholders());
    }

}
