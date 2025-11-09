/*
 * Copyright 2025 Red Hat, Inc. and/or its affiliates
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

package org.iamshield.crl.infinispan;

import org.infinispan.Cache;
import org.iamshield.Config;
import org.iamshield.cluster.ClusterEvent;
import org.iamshield.cluster.ClusterProvider;
import org.iamshield.connections.infinispan.InfinispanConnectionProvider;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.IAMShieldSessionFactory;
import org.iamshield.models.cache.CacheCrlProvider;
import org.iamshield.models.cache.CacheCrlProviderFactory;

public class InfinispanCacheCrlProviderFactory implements CacheCrlProviderFactory {

    public static final String PROVIDER_ID = "infinispan";

    public static final String CRL_CLEAR_CACHE_EVENTS = "CRL_CLEAR_CACHE_EVENTS";

    private volatile Cache<String, X509CRLEntry> crlCache;

    @Override
    public CacheCrlProvider create(IAMShieldSession session) {
        lazyInit(session);
        return new InfinispanCacheCrlProvider(session, crlCache);
    }

    private void lazyInit(IAMShieldSession session) {
        if (crlCache == null) {
            synchronized (this) {
                if (crlCache == null) {
                    crlCache = session.getProvider(InfinispanConnectionProvider.class).getCache(InfinispanConnectionProvider.CRL_CACHE_NAME);
                    ClusterProvider cluster = session.getProvider(ClusterProvider.class);

                    cluster.registerListener(CRL_CLEAR_CACHE_EVENTS, (ClusterEvent event) -> {
                        crlCache.clear();
                    });
                }
            }
        }
    }

    @Override
    public void init(Config.Scope config) {

    }

    @Override
    public void postInit(IAMShieldSessionFactory factory) {

    }

    @Override
    public void close() {

    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }
}
