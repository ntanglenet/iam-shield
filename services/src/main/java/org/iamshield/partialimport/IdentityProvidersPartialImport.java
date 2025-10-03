/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.iamshield.partialimport;

import org.iamshield.models.IdentityProviderModel;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.RealmModel;
import org.iamshield.models.utils.IAMShieldModelUtils;
import org.iamshield.models.utils.RepresentationToModel;
import org.iamshield.representations.idm.IdentityProviderRepresentation;
import org.iamshield.representations.idm.PartialImportRepresentation;

import java.util.List;

/**
 * PartialImport handler for Identity Providers.
 *
 * @author Stan Silvert ssilvert@redhat.com (C) 2016 Red Hat Inc.
 */
public class IdentityProvidersPartialImport extends AbstractPartialImport<IdentityProviderRepresentation> {

    @Override
    public List<IdentityProviderRepresentation> getRepList(PartialImportRepresentation partialImportRep) {
        return partialImportRep.getIdentityProviders();
    }

    @Override
    public String getName(IdentityProviderRepresentation idpRep) {
        return idpRep.getAlias();
    }

    @Override
    public String getModelId(RealmModel realm, IAMShieldSession session, IdentityProviderRepresentation idpRep) {
        return session.identityProviders().getByAlias(getName(idpRep)).getInternalId();
    }

    @Override
    public boolean exists(RealmModel realm, IAMShieldSession session, IdentityProviderRepresentation idpRep) {
        return session.identityProviders().getByAlias(getName(idpRep)) != null;
    }

    @Override
    public String existsMessage(RealmModel realm, IdentityProviderRepresentation idpRep) {
        return "Identity Provider '" + getName(idpRep) + "' already exists.";
    }

    @Override
    public ResourceType getResourceType() {
        return ResourceType.IDP;
    }

    @Override
    public void remove(RealmModel realm, IAMShieldSession session, IdentityProviderRepresentation idpRep) {
        session.identityProviders().remove(getName(idpRep));
    }

    @Override
    public void create(RealmModel realm, IAMShieldSession session, IdentityProviderRepresentation idpRep) {
        idpRep.setInternalId(IAMShieldModelUtils.generateId());
        session.identityProviders().create(RepresentationToModel.toModel(realm, idpRep, session));
    }

}
