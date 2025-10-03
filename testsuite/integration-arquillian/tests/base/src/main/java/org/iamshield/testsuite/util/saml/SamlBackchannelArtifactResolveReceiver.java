package org.iamshield.testsuite.util.saml;


import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import jakarta.ws.rs.core.HttpHeaders;
import org.jboss.logging.Logger;
import org.iamshield.common.util.KeyUtils;
import org.iamshield.dom.saml.v2.protocol.ArtifactResolveType;
import org.iamshield.dom.saml.v2.protocol.ArtifactResponseType;
import org.iamshield.dom.saml.v2.protocol.ResponseType;
import org.iamshield.protocol.saml.JaxrsSAML2BindingBuilder;
import org.iamshield.protocol.saml.SamlConfigAttributes;
import org.iamshield.protocol.saml.SamlProtocolUtils;
import org.iamshield.protocol.saml.profile.util.Soap;
import org.iamshield.representations.idm.ClientRepresentation;
import org.iamshield.saml.SAML2LoginResponseBuilder;
import org.iamshield.saml.SignatureAlgorithm;
import org.iamshield.saml.common.util.DocumentUtil;
import org.iamshield.saml.processing.api.saml.v2.response.SAML2Response;
import org.iamshield.saml.processing.core.saml.v2.common.SAMLDocumentHolder;
import org.w3c.dom.Document;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.security.PrivateKey;
import java.security.PublicKey;

public class SamlBackchannelArtifactResolveReceiver implements AutoCloseable {

    private static final Logger LOG = Logger.getLogger(SamlBackchannelArtifactResolveReceiver.class);

    private final HttpServer server;
    private ArtifactResolveType artifactResolve;
    private final String url;
    private final ClientRepresentation samlClient;
    private final PublicKey publicKey;
    private final PrivateKey privateKey;

    public SamlBackchannelArtifactResolveReceiver(int port, ClientRepresentation samlClient, String publicKeyStr, String privateKeyStr) {
        this.samlClient = samlClient;
        publicKey = publicKeyStr == null ? null : org.iamshield.testsuite.util.KeyUtils.publicKeyFromString(publicKeyStr);
        privateKey = privateKeyStr == null ? null : org.iamshield.testsuite.util.KeyUtils.privateKeyFromString(privateKeyStr);
        try {
            InetSocketAddress address = new InetSocketAddress(InetAddress.getByName("localhost"), port);
            server = HttpServer.create(address, 0);
            this.url = "http://" + address.getHostString() + ":" + port;
        } catch (IOException e) {
            throw new RuntimeException("Cannot create http server", e);
        }

        server.createContext("/", new SamlBackchannelArtifactResolveHandler());
        server.setExecutor(null);
        server.start();
    }

    public SamlBackchannelArtifactResolveReceiver(int port, ClientRepresentation samlClient) {
        this(port, samlClient, null, null);
    }

    public String getUrl() {
        return url;
    }

    public boolean isArtifactResolveReceived() {
        return artifactResolve != null;
    }

    public ArtifactResolveType getArtifactResolve() {
        return artifactResolve;
    }

    @Override
    public void close() throws Exception {
        server.stop(0);
    }

    private class SamlBackchannelArtifactResolveHandler implements HttpHandler {
        public void handle(HttpExchange t) throws IOException {
            try {
                t.getResponseHeaders().add(HttpHeaders.CONTENT_TYPE, "text/xml");
                t.sendResponseHeaders(200, 0);

                Document request = Soap.extractSoapMessage(t.getRequestBody());
                LOG.infof("Received ArtifactResolve: %s", DocumentUtil.asString(request));

                SAMLDocumentHolder samlDoc = SAML2Response.getSAML2ObjectFromDocument(request);
                if (!(samlDoc.getSamlObject() instanceof ArtifactResolveType)) {
                    throw new RuntimeException("SamlBackchannelArtifactResolveReceiver received a message that was not ArtifactResolveType");
                }
                artifactResolve = (ArtifactResolveType) samlDoc.getSamlObject();

                // create the login response
                SAML2LoginResponseBuilder loginResponseBuilder = new SAML2LoginResponseBuilder();
                ResponseType loginResponse = loginResponseBuilder
                        .issuer(samlClient.getClientId())
                        .requestIssuer(artifactResolve.getIssuer().getValue())
                        .requestID(artifactResolve.getID())
                        .buildModel();

                Document loginResponseBuilderAsDoc = loginResponseBuilder.buildDocument(loginResponse);

                // bundle the login response in the Artifact Response
                ArtifactResponseType artifactResponse = SamlProtocolUtils.buildArtifactResponse(loginResponseBuilderAsDoc);
                artifactResponse.setInResponseTo(artifactResolve.getID());
                JaxrsSAML2BindingBuilder soapBinding = new JaxrsSAML2BindingBuilder(null);
                if (requiresClientSignature(samlClient)) {
                    soapBinding.signatureAlgorithm(getSignatureAlgorithm(samlClient))
                            .signWith(KeyUtils.createKeyId(privateKey), privateKey, publicKey, null)
                            .signDocument();
                }
                Document artifactResponseAsDoc = SAML2Response.convert(artifactResponse);
                Document soapDoc = soapBinding.soapBinding(artifactResponseAsDoc).getDocument();

                LOG.infof("Sending ArtifactResponse: %s", DocumentUtil.asString(soapDoc));

                // send login response
                OutputStream os = t.getResponseBody();
                os.write(Soap.createMessage().addToBody(soapDoc).getBytes());
                os.close();
            } catch (Exception ex) {
                t.sendResponseHeaders(500, 0);
            }
        }
    }

    private SignatureAlgorithm getSignatureAlgorithm(ClientRepresentation client) {
        String alg = client.getAttributes().get(SamlConfigAttributes.SAML_SIGNATURE_ALGORITHM);
        if (alg != null) {
            SignatureAlgorithm algorithm = SignatureAlgorithm.valueOf(alg);
            if (algorithm != null)
                return algorithm;
        }
        return SignatureAlgorithm.RSA_SHA256;
    }

    public boolean requiresClientSignature(ClientRepresentation client) {
        return "true".equals(client.getAttributes().get(SamlConfigAttributes.SAML_CLIENT_SIGNATURE_ATTRIBUTE));
    }
}


