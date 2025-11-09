package org.iamshield.operator.controllers;

import io.fabric8.kubernetes.api.model.Secret;
import io.fabric8.kubernetes.api.model.SecretBuilder;
import io.fabric8.kubernetes.client.utils.KubernetesResourceUtil;
import io.javaoperatorsdk.operator.api.config.informer.Informer;
import io.javaoperatorsdk.operator.api.reconciler.Context;
import io.javaoperatorsdk.operator.processing.dependent.kubernetes.CRUDKubernetesDependentResource;
import io.javaoperatorsdk.operator.processing.dependent.kubernetes.KubernetesDependent;

import org.iamshield.operator.Constants;
import org.iamshield.operator.Utils;
import org.iamshield.operator.crds.v2alpha1.realmimport.KeycloakRealmImport;

@KubernetesDependent(
        informer = @Informer(labelSelector = Constants.DEFAULT_LABELS_AS_STRING)
)
public class IAMShieldRealmImportSecretDependentResource extends CRUDKubernetesDependentResource<Secret, KeycloakRealmImport> {

    public static final String DEPENDENT_NAME = "realm-import-secret";

    public IAMShieldRealmImportSecretDependentResource() {
        super(Secret.class);
    }

    @Override
    protected Secret desired(KeycloakRealmImport primary, Context<KeycloakRealmImport> context) {
        var fileName = primary.getRealmName() + "-realm.json";
        var content = context.getClient().getKubernetesSerialization().asJson(primary.getSpec().getRealm());

        return new SecretBuilder()
                .withNewMetadata()
                .withName(getSecretName(primary))
                .withNamespace(primary.getMetadata().getNamespace())
                // this is labeling the instance as the realm import, not the keycloak
                .addToLabels(Utils.allInstanceLabels(primary))
                .endMetadata()
                .addToData(fileName, Utils.asBase64(content))
                .build();
    }

    public static String getSecretName(KeycloakRealmImport realmCR) {
        return KubernetesResourceUtil.sanitizeName(realmCR.getSpec().getKeycloakCRName() + "-" + realmCR.getRealmName() + "-realm");
    }

}
