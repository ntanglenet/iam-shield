/*
 * Copyright 2022 Red Hat, Inc. and/or its affiliates
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
package org.iamshield.authorization.jpa.store;

import static org.iamshield.authorization.UserManagedPermissionUtil.updatePolicy;

import jakarta.persistence.EntityManager;

import org.iamshield.authorization.jpa.entities.PermissionTicketEntity;
import org.iamshield.authorization.jpa.entities.PolicyEntity;
import org.iamshield.authorization.jpa.entities.ScopeEntity;
import org.iamshield.authorization.model.PermissionTicket;
import org.iamshield.authorization.model.Policy;
import org.iamshield.authorization.model.Resource;
import org.iamshield.authorization.model.ResourceServer;
import org.iamshield.authorization.model.Scope;
import org.iamshield.authorization.store.StoreFactory;
import org.iamshield.models.jpa.JpaModel;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
public class PermissionTicketAdapter implements PermissionTicket, JpaModel<PermissionTicketEntity> {

    private final EntityManager entityManager;
    private final PermissionTicketEntity entity;
    private final StoreFactory storeFactory;

    public PermissionTicketAdapter(PermissionTicketEntity entity, EntityManager entityManager, StoreFactory storeFactory) {
        this.entity = entity;
        this.entityManager = entityManager;
        this.storeFactory = storeFactory;
    }

    @Override
    public PermissionTicketEntity getEntity() {
        return entity;
    }

    @Override
    public String getId() {
        return entity.getId();
    }

    @Override
    public String getOwner() {
        return entity.getOwner();
    }

    @Override
    public String getRequester() {
        return entity.getRequester();
    }

    @Override
    public boolean isGranted() {
        return entity.isGranted();
    }

    @Override
    public Long getCreatedTimestamp() {
        return entity.getCreatedTimestamp();
    }

    @Override
    public Long getGrantedTimestamp() {
        return entity.getGrantedTimestamp();
    }

    @Override
    public void setGrantedTimestamp(Long millis) {
        entity.setGrantedTimestamp(millis);
        updatePolicy(this, storeFactory);
    }

    @Override
    public ResourceServer getResourceServer() {
        return storeFactory.getResourceServerStore().findById(entity.getResourceServer().getId());
    }

    @Override
    public Policy getPolicy() {
        PolicyEntity policy = entity.getPolicy();

        if (policy == null) {
            return null;
        }

        ResourceServer resourceServer = storeFactory.getResourceServerStore().findById(entity.getResourceServer().getId());
        return storeFactory.getPolicyStore().findById(resourceServer, policy.getId());
    }

    @Override
    public void setPolicy(Policy policy) {
        if (policy != null) {
            entity.setPolicy(entityManager.getReference(PolicyEntity.class, policy.getId()));
        }
    }

    @Override
    public Resource getResource() {
        return storeFactory.getResourceStore().findById(getResourceServer(), entity.getResource().getId());
    }

    @Override
    public Scope getScope() {
        ScopeEntity scope = entity.getScope();

        if (scope == null) {
            return null;
        }

        return storeFactory.getScopeStore().findById(getResourceServer(), scope.getId());
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || !(o instanceof PermissionTicket)) return false;

        PermissionTicket that = (PermissionTicket) o;
        return that.getId().equals(getId());
    }

    @Override
    public int hashCode() {
        return getId().hashCode();
    }

    public static PermissionTicketEntity toEntity(EntityManager em, PermissionTicket permission) {
        if (permission instanceof PermissionTicketAdapter) {
            return ((PermissionTicketAdapter)permission).getEntity();
        } else {
            return em.getReference(PermissionTicketEntity.class, permission.getId());
        }
    }



}
