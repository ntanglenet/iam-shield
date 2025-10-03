package org.iamshield.testsuite.util;

import org.apache.tools.ant.filters.StringInputStream;
import org.iamshield.adapters.saml.SamlDeployment;
import org.iamshield.adapters.saml.config.parsers.DeploymentBuilder;
import org.iamshield.adapters.saml.config.parsers.ResourceLoader;
import org.iamshield.admin.client.resource.ClientsResource;
import org.iamshield.dom.saml.v2.metadata.EntityDescriptorType;
import org.iamshield.dom.saml.v2.metadata.SPSSODescriptorType;
import org.iamshield.protocol.saml.installation.SamlSPDescriptorClientInstallation;
import org.iamshield.representations.idm.ClientRepresentation;
import org.iamshield.saml.common.exceptions.ParsingException;
import org.iamshield.saml.processing.core.parsers.saml.SAMLParser;
import org.iamshield.testsuite.utils.arquillian.DeploymentArchiveProcessorUtils;
import org.iamshield.testsuite.utils.io.IOUtil;
import org.w3c.dom.Document;

import java.io.InputStream;

public class SamlUtils {
    public static SamlDeployment getSamlDeploymentForClient(String client) throws ParsingException {
        InputStream is = SamlUtils.class.getResourceAsStream("/adapter-test/keycloak-saml/" + client + "/WEB-INF/keycloak-saml.xml");

        // InputStream -> Document
        Document doc = IOUtil.loadXML(is);

        // Modify saml deployment the same way as before deploying to real app server
        DeploymentArchiveProcessorUtils.modifySAMLDocument(doc);

        // Document -> InputStream
        InputStream isProcessed = IOUtil.documentToInputStream(doc);

        // InputStream -> SamlDeployment
        ResourceLoader loader = new ResourceLoader() {
            @Override
            public InputStream getResourceAsStream(String resource) {
                return getClass().getResourceAsStream("/adapter-test/keycloak-saml/" + client + resource);
            }
        };
        return new DeploymentBuilder().build(isProcessed, loader);
    }

    public static SPSSODescriptorType getSPInstallationDescriptor(ClientsResource res, String clientId) throws ParsingException {
        String spDescriptorString = res.findByClientId(clientId).stream().findFirst()
                .map(ClientRepresentation::getId)
                .map(res::get)
                .map(clientResource -> clientResource.getInstallationProvider(SamlSPDescriptorClientInstallation.SAML_CLIENT_INSTALATION_SP_DESCRIPTOR))
                .orElseThrow(() -> new RuntimeException("Missing descriptor"));

        SAMLParser parser = SAMLParser.getInstance();
        EntityDescriptorType o = (EntityDescriptorType) parser.parse(new StringInputStream(spDescriptorString));
        return o.getChoiceType().get(0).getDescriptors().get(0).getSpDescriptor();
    }
}
