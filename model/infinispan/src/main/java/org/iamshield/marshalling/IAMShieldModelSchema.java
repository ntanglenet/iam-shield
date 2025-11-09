/*
 * Copyright 2024 Red Hat, Inc. and/or its affiliates
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

package org.iamshield.marshalling;

import java.util.Objects;
import java.util.Optional;

import org.infinispan.protostream.FileDescriptorSource;
import org.infinispan.protostream.GeneratedSchema;
import org.infinispan.protostream.annotations.ProtoSchema;
import org.infinispan.protostream.annotations.ProtoSyntax;
import org.infinispan.protostream.config.Configuration;
import org.infinispan.protostream.descriptors.Descriptor;
import org.infinispan.protostream.descriptors.FileDescriptor;
import org.infinispan.protostream.impl.parser.ProtostreamProtoParser;
import org.infinispan.protostream.types.java.CommonTypes;
import org.iamshield.cluster.infinispan.LockEntry;
import org.iamshield.cluster.infinispan.LockEntryPredicate;
import org.iamshield.cluster.infinispan.WrapperClusterEvent;
import org.iamshield.component.ComponentModel;
import org.iamshield.jgroups.certificates.ReloadCertificateFunction;
import org.iamshield.keys.infinispan.PublicKeyStorageInvalidationEvent;
import org.iamshield.models.UserSessionModel;
import org.iamshield.models.cache.infinispan.ClearCacheEvent;
import org.iamshield.models.cache.infinispan.authorization.events.PermissionTicketRemovedEvent;
import org.iamshield.models.cache.infinispan.authorization.events.PermissionTicketUpdatedEvent;
import org.iamshield.models.cache.infinispan.authorization.events.PolicyRemovedEvent;
import org.iamshield.models.cache.infinispan.authorization.events.PolicyUpdatedEvent;
import org.iamshield.models.cache.infinispan.authorization.events.ResourceRemovedEvent;
import org.iamshield.models.cache.infinispan.authorization.events.ResourceServerRemovedEvent;
import org.iamshield.models.cache.infinispan.authorization.events.ResourceServerUpdatedEvent;
import org.iamshield.models.cache.infinispan.authorization.events.ResourceUpdatedEvent;
import org.iamshield.models.cache.infinispan.authorization.events.ScopeRemovedEvent;
import org.iamshield.models.cache.infinispan.authorization.events.ScopeUpdatedEvent;
import org.iamshield.models.cache.infinispan.authorization.stream.InResourcePredicate;
import org.iamshield.models.cache.infinispan.authorization.stream.InResourceServerPredicate;
import org.iamshield.models.cache.infinispan.authorization.stream.InScopePredicate;
import org.iamshield.models.cache.infinispan.events.AuthenticationSessionAuthNoteUpdateEvent;
import org.iamshield.models.cache.infinispan.events.CacheKeyInvalidatedEvent;
import org.iamshield.models.cache.infinispan.events.ClientAddedEvent;
import org.iamshield.models.cache.infinispan.events.ClientRemovedEvent;
import org.iamshield.models.cache.infinispan.events.ClientScopeAddedEvent;
import org.iamshield.models.cache.infinispan.events.ClientScopeRemovedEvent;
import org.iamshield.models.cache.infinispan.events.ClientUpdatedEvent;
import org.iamshield.models.cache.infinispan.events.GroupAddedEvent;
import org.iamshield.models.cache.infinispan.events.GroupMovedEvent;
import org.iamshield.models.cache.infinispan.events.GroupRemovedEvent;
import org.iamshield.models.cache.infinispan.events.GroupUpdatedEvent;
import org.iamshield.models.cache.infinispan.events.RealmRemovedEvent;
import org.iamshield.models.cache.infinispan.events.RealmUpdatedEvent;
import org.iamshield.models.cache.infinispan.events.RoleAddedEvent;
import org.iamshield.models.cache.infinispan.events.RoleRemovedEvent;
import org.iamshield.models.cache.infinispan.events.RoleUpdatedEvent;
import org.iamshield.models.cache.infinispan.events.UserCacheRealmInvalidationEvent;
import org.iamshield.models.cache.infinispan.events.UserConsentsUpdatedEvent;
import org.iamshield.models.cache.infinispan.events.UserFederationLinkRemovedEvent;
import org.iamshield.models.cache.infinispan.events.UserFederationLinkUpdatedEvent;
import org.iamshield.models.cache.infinispan.events.UserFullInvalidationEvent;
import org.iamshield.models.cache.infinispan.events.UserUpdatedEvent;
import org.iamshield.models.cache.infinispan.stream.GroupListPredicate;
import org.iamshield.models.cache.infinispan.stream.HasRolePredicate;
import org.iamshield.models.cache.infinispan.stream.InClientPredicate;
import org.iamshield.models.cache.infinispan.stream.InGroupPredicate;
import org.iamshield.models.cache.infinispan.stream.InIdentityProviderPredicate;
import org.iamshield.models.cache.infinispan.stream.InRealmPredicate;
import org.iamshield.models.sessions.infinispan.changes.ReplaceFunction;
import org.iamshield.models.sessions.infinispan.changes.SessionEntityWrapper;
import org.iamshield.models.sessions.infinispan.changes.sessions.SessionData;
import org.iamshield.models.sessions.infinispan.entities.AuthenticatedClientSessionEntity;
import org.iamshield.models.sessions.infinispan.entities.AuthenticatedClientSessionStore;
import org.iamshield.models.sessions.infinispan.entities.AuthenticationSessionEntity;
import org.iamshield.models.sessions.infinispan.entities.ClientSessionKey;
import org.iamshield.models.sessions.infinispan.entities.EmbeddedClientSessionKey;
import org.iamshield.models.sessions.infinispan.entities.LoginFailureEntity;
import org.iamshield.models.sessions.infinispan.entities.LoginFailureKey;
import org.iamshield.models.sessions.infinispan.entities.RemoteAuthenticatedClientSessionEntity;
import org.iamshield.models.sessions.infinispan.entities.RemoteUserSessionEntity;
import org.iamshield.models.sessions.infinispan.entities.RootAuthenticationSessionEntity;
import org.iamshield.models.sessions.infinispan.entities.SingleUseObjectValueEntity;
import org.iamshield.models.sessions.infinispan.entities.UserSessionEntity;
import org.iamshield.models.sessions.infinispan.events.RealmRemovedSessionEvent;
import org.iamshield.models.sessions.infinispan.events.RemoveAllUserLoginFailuresEvent;
import org.iamshield.models.sessions.infinispan.events.RemoveUserSessionsEvent;
import org.iamshield.models.sessions.infinispan.stream.AuthClientSessionSetMapper;
import org.iamshield.models.sessions.infinispan.stream.CollectionToStreamMapper;
import org.iamshield.models.sessions.infinispan.stream.GroupAndCountCollectorSupplier;
import org.iamshield.models.sessions.infinispan.stream.MapEntryToKeyMapper;
import org.iamshield.models.sessions.infinispan.stream.SessionPredicate;
import org.iamshield.models.sessions.infinispan.stream.SessionUnwrapMapper;
import org.iamshield.models.sessions.infinispan.stream.SessionWrapperPredicate;
import org.iamshield.models.sessions.infinispan.stream.UserSessionPredicate;
import org.iamshield.sessions.CommonClientSessionModel;
import org.iamshield.storage.UserStorageProviderModel;
import org.iamshield.storage.managers.UserStorageSyncManager;

@ProtoSchema(
        syntax = ProtoSyntax.PROTO3,
        schemaPackageName = Marshalling.PROTO_SCHEMA_PACKAGE,
        schemaFilePath = "proto/generated",
        allowNullFields = true,

        // common-types for UUID
        dependsOn = CommonTypes.class,

        includeClasses = {
                // Model
                UserSessionModel.State.class,
                CommonClientSessionModel.ExecutionStatus.class,
                ComponentModel.MultiMapEntry.class,
                UserStorageProviderModel.class,
                UserStorageSyncManager.UserStorageProviderClusterEvent.class,

                // clustering.infinispan package
                LockEntry.class,
                LockEntryPredicate.class,
                WrapperClusterEvent.class,
                WrapperClusterEvent.SiteFilter.class,

                // keys.infinispan package
                PublicKeyStorageInvalidationEvent.class,

                // models.cache.infinispan
                ClearCacheEvent.class,

                //models.cache.infinispan.authorization.events package
                PermissionTicketRemovedEvent.class,
                PermissionTicketUpdatedEvent.class,
                PolicyUpdatedEvent.class,
                PolicyRemovedEvent.class,
                ResourceUpdatedEvent.class,
                ResourceRemovedEvent.class,
                ResourceServerUpdatedEvent.class,
                ResourceServerRemovedEvent.class,
                ScopeUpdatedEvent.class,
                ScopeRemovedEvent.class,

                // models.sessions.infinispan.changes package
                SessionEntityWrapper.class,

                // models.sessions.infinispan.changes.sessions package
                SessionData.class,

                // models.cache.infinispan.authorization.stream package
                InResourcePredicate.class,
                InResourceServerPredicate.class,
                InScopePredicate.class,

                // models.sessions.infinispan.events package
                RealmRemovedSessionEvent.class,
                RemoveAllUserLoginFailuresEvent.class,
                RemoveUserSessionsEvent.class,

                // models.sessions.infinispan.stream package
                SessionPredicate.class,
                SessionWrapperPredicate.class,
                UserSessionPredicate.class,

                // models.cache.infinispan.stream package
                GroupListPredicate.class,
                HasRolePredicate.class,
                InClientPredicate.class,
                InGroupPredicate.class,
                InIdentityProviderPredicate.class,
                InRealmPredicate.class,

                // models.cache.infinispan.events package
                AuthenticationSessionAuthNoteUpdateEvent.class,
                CacheKeyInvalidatedEvent.class,
                ClientAddedEvent.class,
                ClientUpdatedEvent.class,
                ClientRemovedEvent.class,
                ClientScopeAddedEvent.class,
                ClientScopeRemovedEvent.class,
                GroupAddedEvent.class,
                GroupMovedEvent.class,
                GroupRemovedEvent.class,
                GroupUpdatedEvent.class,
                RealmUpdatedEvent.class,
                RealmRemovedEvent.class,
                RoleAddedEvent.class,
                RoleUpdatedEvent.class,
                RoleRemovedEvent.class,
                UserCacheRealmInvalidationEvent.class,
                UserConsentsUpdatedEvent.class,
                UserFederationLinkRemovedEvent.class,
                UserFederationLinkUpdatedEvent.class,
                UserFullInvalidationEvent.class,
                UserUpdatedEvent.class,

                // sessions.infinispan.entities package
                AuthenticatedClientSessionStore.class,
                AuthenticatedClientSessionEntity.class,
                AuthenticationSessionEntity.class,
                ClientSessionKey.class,
                EmbeddedClientSessionKey.class,
                LoginFailureEntity.class,
                LoginFailureKey.class,
                RemoteAuthenticatedClientSessionEntity.class,
                RemoteUserSessionEntity.class,
                RootAuthenticationSessionEntity.class,
                SingleUseObjectValueEntity.class,
                UserSessionEntity.class,
                ReplaceFunction.class,

                // sessions.infinispan.stream
                AuthClientSessionSetMapper.class,
                CollectionToStreamMapper.class,
                GroupAndCountCollectorSupplier.class,
                MapEntryToKeyMapper.class,
                SessionUnwrapMapper.class,

                // infinispan.module.certificates
                ReloadCertificateFunction.class,
        }
)
public interface IAMShieldModelSchema extends GeneratedSchema {

    IAMShieldModelSchema INSTANCE = new IAMShieldModelSchemaImpl();

    /**
     * Parses a Google Protocol Buffers schema file.
     */
    static FileDescriptor parseProtoSchema(String fileContent) {
        var files = FileDescriptorSource.fromString("a", fileContent);
        var builder = Configuration.builder();
        IAMShieldIndexSchemaUtil.configureAnnotationProcessor(builder);
        var parser = new ProtostreamProtoParser(builder.build());
        return parser.parse(files).get("a");
    }

    /**
     * Finds an entity in a Google Protocol Buffers schema file
     */
    static Optional<Descriptor> findEntity(FileDescriptor fileDescriptor, String entity) {
        return fileDescriptor.getMessageTypes().stream()
                .filter(descriptor -> Objects.equals(entity, descriptor.getFullName()))
                .findFirst();
    }
}
