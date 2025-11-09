package org.iamshield.testsuite.util;

import org.iamshield.admin.client.resource.ComponentResource;
import org.iamshield.admin.client.resource.RealmResource;
import org.iamshield.common.util.Base64;
import org.iamshield.common.util.CertificateUtils;
import org.iamshield.common.util.MultivaluedHashMap;
import org.iamshield.common.util.PemUtils;
import org.iamshield.crypto.KeyType;
import org.iamshield.keys.Attributes;
import org.iamshield.keys.ImportedRsaKeyProviderFactory;
import org.iamshield.keys.KeyProvider;
import org.iamshield.representations.idm.ComponentRepresentation;
import org.iamshield.representations.idm.RealmRepresentation;
import org.iamshield.testsuite.admin.ApiUtil;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.stream.Collectors;

import jakarta.ws.rs.core.Response;

/**
 * @author <a href="mailto:bruno@abstractj.org">Bruno Oliveira</a>.
 */
public class RealmManager {

    private static RealmResource realm;

    private RealmManager() {
    }

    public static RealmManager realm(RealmResource realm) {
        RealmManager.realm = realm;
        return new RealmManager();
    }

    public RealmManager accessCodeLifeSpan(Integer accessCodeLifespan) {
        RealmRepresentation realmRepresentation = realm.toRepresentation();
        realmRepresentation.setAccessCodeLifespan(accessCodeLifespan);
        realm.update(realmRepresentation);
        return this;
    }

    public RealmManager verifyEmail(Boolean enabled) {
        RealmRepresentation rep = realm.toRepresentation();
        rep.setVerifyEmail(enabled);
        realm.update(rep);
        return this;
    }

    public RealmManager passwordPolicy(String passwordPolicy) {
        RealmRepresentation rep = realm.toRepresentation();
        rep.setPasswordPolicy(passwordPolicy);
        realm.update(rep);
        return this;
    }

    public RealmManager revokeRefreshToken(boolean enable) {
        RealmRepresentation rep = realm.toRepresentation();
        rep.setRevokeRefreshToken(enable);
        realm.update(rep);
        return this;
    }

    public RealmManager refreshTokenMaxReuse(int refreshTokenMaxReuse) {
        RealmRepresentation rep = realm.toRepresentation();
        rep.setRefreshTokenMaxReuse(refreshTokenMaxReuse);
        realm.update(rep);
        return this;
    }

    public void generateKeys() {
        RealmRepresentation rep = realm.toRepresentation();

        KeyPair keyPair;
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            keyPair = generator.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        rep.setPrivateKey(Base64.encodeBytes(keyPair.getPrivate().getEncoded()));
        rep.setPublicKey(Base64.encodeBytes(keyPair.getPublic().getEncoded()));
        X509Certificate certificate;
        try {
            certificate = CertificateUtils.generateV1SelfSignedCertificate(keyPair, rep.getId());
            rep.setCertificate(Base64.encodeBytes(certificate.getEncoded()));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        rep.setCodeSecret(org.iamshield.models.utils.IAMShieldModelUtils.generateCodeSecret());
        realm.update(rep);
    }

    public void keyPair(String privateKey, String publicKey) {
        RealmRepresentation rep = realm.toRepresentation();
        rep.setPrivateKey(privateKey);
        rep.setPublicKey(publicKey);
        realm.update(rep);
    }

    public String generateNewRsaKey(KeyPair keyPair, String name) {
        RealmRepresentation rep = realm.toRepresentation();

        Certificate certificate = CertificateUtils.generateV1SelfSignedCertificate(keyPair, "test");
        String certificatePem = PemUtils.encodeCertificate(certificate);

        ComponentRepresentation keyProviderRepresentation = new ComponentRepresentation();
        keyProviderRepresentation.setName(name);
        keyProviderRepresentation.setParentId(rep.getId());
        keyProviderRepresentation.setProviderId(ImportedRsaKeyProviderFactory.ID);
        keyProviderRepresentation.setProviderType(KeyProvider.class.getName());

        MultivaluedHashMap<String, String> config = new MultivaluedHashMap<>();
        config.putSingle(Attributes.PRIVATE_KEY_KEY, PemUtils.encodeKey(keyPair.getPrivate()));
        config.putSingle(Attributes.CERTIFICATE_KEY, certificatePem);
        config.putSingle(Attributes.PRIORITY_KEY, "100");
        keyProviderRepresentation.setConfig(config);

        Response response = realm.components().add(keyProviderRepresentation);
        String providerId = ApiUtil.getCreatedId(response);
        response.close();

        deactivateOtherRsaKeys(providerId);

        return providerId;
    }

    private void deactivateOtherRsaKeys(String providerId) {
        List<String> otherRsaKeyProviderIds = realm.keys()
                .getKeyMetadata().getKeys().stream()
                .filter(key -> KeyType.RSA.equals(key.getType()) && !providerId.equals(key.getProviderId()))
                .map(key -> key.getProviderId())
                .collect(Collectors.toList());

        for (String otherRsaKeyProviderId : otherRsaKeyProviderIds) {
            ComponentResource componentResource = realm.components().component(otherRsaKeyProviderId);
            ComponentRepresentation componentRepresentation = componentResource.toRepresentation();
            componentRepresentation.getConfig().putSingle(Attributes.ACTIVE_KEY, "false");
            componentResource.update(componentRepresentation);
        }
    }

    public void ssoSessionMaxLifespan(int ssoSessionMaxLifespan) {
        RealmRepresentation rep = realm.toRepresentation();
        rep.setSsoSessionMaxLifespan(ssoSessionMaxLifespan);
        realm.update(rep);
    }

    public void sslRequired(String sslRequired) {
        RealmRepresentation rep = realm.toRepresentation();
        rep.setSslRequired(sslRequired);
        realm.update(rep);
    }

    public void accessTokenLifespan(int accessTokenLifespan) {
        RealmRepresentation rep = realm.toRepresentation();
        rep.setAccessTokenLifespan(accessTokenLifespan);
        realm.update(rep);
    }

    public RealmManager ssoSessionIdleTimeout(int ssoSessionIdleTimeout) {
        RealmRepresentation rep = realm.toRepresentation();
        rep.setSsoSessionIdleTimeout(ssoSessionIdleTimeout);
        realm.update(rep);
        return this;
    }

    public RealmManager clientSessionMaxLifespan(int clientSessionLaxLifespan) {
        RealmRepresentation rep = realm.toRepresentation();
        rep.setClientSessionMaxLifespan(clientSessionLaxLifespan);
        realm.update(rep);
        return this;
    }

    public RealmManager clientSessionIdleTimeout(int clientSessionIdleTimeout) {
        RealmRepresentation rep = realm.toRepresentation();
        rep.setClientSessionIdleTimeout(clientSessionIdleTimeout);
        realm.update(rep);
        return this;
    }
}