package org.iamshield.testsuite.federation.storage;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.iamshield.admin.client.resource.RealmResource;
import org.iamshield.common.util.MultivaluedHashMap;
import org.iamshield.exportimport.ExportImportConfig;
import org.iamshield.exportimport.ExportImportManager;
import org.iamshield.exportimport.singlefile.SingleFileExportProviderFactory;
import org.iamshield.models.RealmModel;
import org.iamshield.representations.idm.ComponentRepresentation;
import org.iamshield.representations.idm.RealmRepresentation;
import org.iamshield.storage.UserStorageProvider;
import org.iamshield.testsuite.AbstractAuthTest;
import org.iamshield.testsuite.admin.ApiUtil;

import org.iamshield.testsuite.client.IAMShieldTestingClient;
import org.iamshield.testsuite.federation.UserMapStorageFactory;
import org.iamshield.testsuite.util.RealmBuilder;

import java.io.Closeable;
import jakarta.ws.rs.NotFoundException;
import java.io.File;
import java.util.HashSet;
import java.util.Properties;
import java.util.Set;

import static org.junit.Assert.fail;
import static org.iamshield.storage.UserStorageProviderModel.IMPORT_ENABLED;

/**
 *
 * @author tkyjovsk
 */
public class ComponentExportImportTest extends AbstractAuthTest {

    private static final String REALM_NAME = "exported-component";

    private File exportFile;

    @Before
    public void setDirs() {
        exportFile = new File (new File(System.getProperty("auth.server.config.dir", "target")), "singleFile-full.json");
        log.infof("Export file: %s", exportFile);

        // Remove realm if exists
        testingClient.server().run(session -> {
            RealmModel realm = session.realms().getRealmByName(REALM_NAME);
            if (realm != null) {
                session.realms().removeRealm(realm.getId());
            }
        });
    }


    @Override
    public RealmResource testRealmResource() {
        return adminClient.realm(REALM_NAME);
    }


    static void clearExportImportProperties(IAMShieldTestingClient testingClient) {
        testingClient.server().run(session -> {
            // Clear export/import properties after test
            Properties systemProps = System.getProperties();
            Set<String> propsToRemove = new HashSet<>();

            for (Object key : systemProps.keySet()) {
                if (key.toString().startsWith(ExportImportConfig.PREFIX)) {
                    propsToRemove.add(key.toString());
                }
            }

            for (String propToRemove : propsToRemove) {
                systemProps.remove(propToRemove);
            }
        });
    }


    protected String addComponent(ComponentRepresentation component) {
        return ApiUtil.getCreatedId(testRealmResource().components().add(component));
    }

    @Test
    public void testSingleFile() {
        clearExportImportProperties(testingClient);

        RealmRepresentation realmRep = RealmBuilder.create()
                .name(REALM_NAME)
                .build();
        adminClient.realms().create(realmRep);
        String realmId = testRealmResource().toRepresentation().getId();

        ComponentRepresentation parentComponent = new ComponentRepresentation();
        parentComponent.setParentId(realmId);
        parentComponent.setName("parent");
        parentComponent.setSubType("subtype");
        parentComponent.setProviderId(UserMapStorageFactory.PROVIDER_ID);
        parentComponent.setProviderType(UserStorageProvider.class.getName());
        parentComponent.setConfig(new MultivaluedHashMap<>());
        parentComponent.getConfig().putSingle("priority", Integer.toString(0));
        parentComponent.getConfig().putSingle("attr", "value");
        parentComponent.getConfig().putSingle(IMPORT_ENABLED, Boolean.toString(false));
        String parentComponentId = addComponent(parentComponent);

        ComponentRepresentation subcomponent = new ComponentRepresentation();
        subcomponent.setParentId(parentComponentId);
        subcomponent.setName("child");
        subcomponent.setSubType("subtype2");
        subcomponent.setProviderId(UserMapStorageFactory.PROVIDER_ID);
        subcomponent.setProviderType(UserStorageProvider.class.getName());
        subcomponent.setConfig(new MultivaluedHashMap<>());
        subcomponent.getConfig().putSingle("priority", Integer.toString(0));
        subcomponent.getConfig().putSingle("attr", "value2");
        subcomponent.getConfig().putSingle(IMPORT_ENABLED, Boolean.toString(false));
        String subcomponentId = addComponent(subcomponent);

        final String exportFilePath = exportFile.getAbsolutePath();

        // export 
        testingClient.server().run(session -> {
            ExportImportConfig.setProvider(SingleFileExportProviderFactory.PROVIDER_ID);
            ExportImportConfig.setFile(exportFilePath);
            ExportImportConfig.setRealmName(REALM_NAME);
            try (Closeable c = ExportImportConfig.setAction(ExportImportConfig.ACTION_EXPORT)) {
                new ExportImportManager(session).runExport();
            }
        });

        getCleanup().addCleanup(testRealmResource()::remove);
        testRealmResource().remove();

        try {
            testRealmResource().toRepresentation();
            Assert.fail("Realm wasn't expected to be found");
        } catch (NotFoundException nfe) {
            // Expected
        }

        // import 
        testingClient.server().run(session -> {
            Assert.assertNull(session.realms().getRealmByName(REALM_NAME));
            try (Closeable c = ExportImportConfig.setAction(ExportImportConfig.ACTION_IMPORT)) {
                new ExportImportManager(session).runImport();
            }
        });

        // Assert realm was imported
        Assert.assertNotNull(testRealmResource().toRepresentation());

        try {
            parentComponent = testRealmResource().components().component(parentComponentId).toRepresentation();
            subcomponent = testRealmResource().components().component(subcomponentId).toRepresentation();
        } catch (NotFoundException nfe) {
            fail("Components not found after import.");
        }

        Assert.assertEquals(parentComponent.getParentId(), realmId);
        Assert.assertEquals(parentComponent.getName(), "parent");
        Assert.assertEquals(parentComponent.getSubType(), "subtype");
        Assert.assertEquals(parentComponent.getProviderId(), UserMapStorageFactory.PROVIDER_ID);
        Assert.assertEquals(parentComponent.getProviderType(), UserStorageProvider.class.getName());
        Assert.assertEquals(parentComponent.getConfig().getFirst("attr"), "value");

        Assert.assertEquals(subcomponent.getParentId(), parentComponent.getId());
        Assert.assertEquals(subcomponent.getName(), "child");
        Assert.assertEquals(subcomponent.getSubType(), "subtype2");
        Assert.assertEquals(subcomponent.getProviderId(), UserMapStorageFactory.PROVIDER_ID);
        Assert.assertEquals(subcomponent.getProviderType(), UserStorageProvider.class.getName());
        Assert.assertEquals(subcomponent.getConfig().getFirst("attr"), "value2");

    }

}
