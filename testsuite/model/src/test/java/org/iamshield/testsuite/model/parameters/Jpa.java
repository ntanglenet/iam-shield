/*
 * Copyright 2020 Red Hat, Inc. and/or its affiliates
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
package org.iamshield.testsuite.model.parameters;

import java.util.Set;

import com.google.common.collect.ImmutableSet;
import org.iamshield.authorization.jpa.store.JPAAuthorizationStoreFactory;
import org.iamshield.broker.provider.IdentityProviderFactory;
import org.iamshield.broker.provider.IdentityProviderSpi;
import org.iamshield.connections.jpa.DefaultJpaConnectionProviderFactory;
import org.iamshield.connections.jpa.JpaConnectionSpi;
import org.iamshield.connections.jpa.updater.JpaUpdaterProviderFactory;
import org.iamshield.connections.jpa.updater.JpaUpdaterSpi;
import org.iamshield.connections.jpa.updater.liquibase.conn.LiquibaseConnectionProviderFactory;
import org.iamshield.connections.jpa.updater.liquibase.conn.LiquibaseConnectionSpi;
import org.iamshield.connections.jpa.updater.liquibase.lock.LiquibaseDBLockProviderFactory;
import org.iamshield.events.jpa.JpaEventStoreProviderFactory;
import org.iamshield.infinispan.util.InfinispanUtils;
import org.iamshield.migration.MigrationProviderFactory;
import org.iamshield.migration.MigrationSpi;
import org.iamshield.models.IdentityProviderStorageSpi;
import org.iamshield.models.UserSessionSpi;
import org.iamshield.models.dblock.DBLockSpi;
import org.iamshield.models.jpa.JpaClientProviderFactory;
import org.iamshield.models.jpa.JpaClientScopeProviderFactory;
import org.iamshield.models.jpa.JpaGroupProviderFactory;
import org.iamshield.models.jpa.JpaIdentityProviderStorageProviderFactory;
import org.iamshield.models.jpa.JpaRealmProviderFactory;
import org.iamshield.models.jpa.JpaRoleProviderFactory;
import org.iamshield.models.jpa.JpaUserProviderFactory;
import org.iamshield.models.jpa.session.JpaRevokedTokensPersisterProviderFactory;
import org.iamshield.models.jpa.session.JpaUserSessionPersisterProviderFactory;
import org.iamshield.models.session.RevokedTokenPersisterSpi;
import org.iamshield.models.session.UserSessionPersisterSpi;
import org.iamshield.organization.OrganizationSpi;
import org.iamshield.organization.jpa.JpaOrganizationProviderFactory;
import org.iamshield.protocol.LoginProtocolFactory;
import org.iamshield.protocol.LoginProtocolSpi;
import org.iamshield.provider.ProviderFactory;
import org.iamshield.provider.Spi;
import org.iamshield.storage.DatastoreSpi;
import org.iamshield.storage.datastore.DefaultDatastoreProviderFactory;
import org.iamshield.testsuite.model.Config;
import org.iamshield.testsuite.model.IAMShieldModelParameters;

/**
 *
 * @author hmlnarik
 */
public class Jpa extends IAMShieldModelParameters {

    static final Set<Class<? extends Spi>> ALLOWED_SPIS = ImmutableSet.<Class<? extends Spi>>builder()
      // jpa-specific
      .add(JpaConnectionSpi.class)
      .add(JpaUpdaterSpi.class)
      .add(LiquibaseConnectionSpi.class)
      .add(UserSessionPersisterSpi.class)
      .add(RevokedTokenPersisterSpi.class)

      .add(DatastoreSpi.class)

      //required for migrateModel
      .add(MigrationSpi.class)
      .add(LoginProtocolSpi.class)

      .add(DBLockSpi.class)

      //required for FederatedIdentityModel
      .add(IdentityProviderStorageSpi.class)
      .add(IdentityProviderSpi.class)

      .add(OrganizationSpi.class)

      .build();

    static final Set<Class<? extends ProviderFactory>> ALLOWED_FACTORIES = ImmutableSet.<Class<? extends ProviderFactory>>builder()
      // jpa-specific
      .add(DefaultDatastoreProviderFactory.class)

      .add(DefaultJpaConnectionProviderFactory.class)
      .add(JPAAuthorizationStoreFactory.class)
      .add(JpaClientProviderFactory.class)
      .add(JpaClientScopeProviderFactory.class)
      .add(JpaEventStoreProviderFactory.class)
      .add(JpaGroupProviderFactory.class)
      .add(JpaIdentityProviderStorageProviderFactory.class)
      .add(JpaRealmProviderFactory.class)
      .add(JpaRoleProviderFactory.class)
      .add(JpaUpdaterProviderFactory.class)
      .add(JpaUserProviderFactory.class)
      .add(LiquibaseConnectionProviderFactory.class)
      .add(LiquibaseDBLockProviderFactory.class)
      .add(JpaUserSessionPersisterProviderFactory.class)
      .add(JpaRevokedTokensPersisterProviderFactory.class)

      //required for migrateModel
      .add(MigrationProviderFactory.class)
      .add(LoginProtocolFactory.class)

      //required for FederatedIdentityModel
      .add(IdentityProviderFactory.class)

      .add(JpaOrganizationProviderFactory.class)

      .build();

    public Jpa() {
        super(ALLOWED_SPIS, ALLOWED_FACTORIES);
    }


    @Override
    public void updateConfig(Config cf) {
        updateConfigForJpa(cf);
    }

    public static void updateConfigForJpa(Config cf) {
        cf.spi("client").defaultProvider("jpa")
          .spi("clientScope").defaultProvider("jpa")
          .spi("group").defaultProvider("jpa")
          .spi("idp").defaultProvider("jpa")
          .spi("role").defaultProvider("jpa")
          .spi("user").defaultProvider("jpa")
          .spi("realm").defaultProvider("jpa")
          .spi("deploymentState").defaultProvider("jpa")
          .spi("dblock").defaultProvider("jpa")
        ;
// Use this for running model tests with Postgres database
//        cf.spi("connectionsJpa")
//                .provider("default")
//                .config("url", "jdbc:postgresql://localhost:5432/keycloakDB")
//                .config("user", "keycloak")
//                .config("password", "pass")
//                .config("driver", "org.postgresql.Driver");
//
    }
}
