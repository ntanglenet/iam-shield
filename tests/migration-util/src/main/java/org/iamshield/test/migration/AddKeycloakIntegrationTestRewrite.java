package org.iamshield.test.migration;

public class AddKeycloakIntegrationTestRewrite extends TestRewrite {

    @Override
    public void rewrite() {
        addImport("org.iamshield.testframework.annotations.IAMShieldIntegrationTest");

        int classDeclaration = findClassDeclaration();
        content.add(classDeclaration, "@IAMShieldIntegrationTest");

        info(classDeclaration,"Added @IAMShieldIntegrationTest");
    }

}
