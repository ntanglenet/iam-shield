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

package org.iamshield.services.resteasy;

import org.iamshield.common.Profile;
import org.iamshield.common.util.MultiSiteUtils;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.IAMShieldSessionFactory;
import org.iamshield.services.error.KcUnrecognizedPropertyExceptionHandler;
import org.iamshield.services.error.IAMShieldErrorHandler;
import org.iamshield.services.error.IAMShieldMismatchedInputExceptionHandler;
import org.iamshield.services.filters.InvalidQueryParameterFilter;
import org.iamshield.services.filters.IAMShieldSecurityHeadersFilter;
import org.iamshield.services.resources.IAMShieldApplication;
import org.iamshield.services.resources.LoadBalancerResource;
import org.iamshield.services.resources.RealmsResource;
import org.iamshield.services.resources.ServerMetadataResource;
import org.iamshield.services.resources.ThemeResource;
import org.iamshield.services.resources.WelcomeResource;
import org.iamshield.services.resources.admin.AdminRoot;
import org.iamshield.services.util.ObjectMapperResolver;

import java.util.HashSet;
import java.util.Set;

public class ResteasyIAMShieldApplication extends IAMShieldApplication {

    protected Set<Object> singletons = new HashSet<>();
    protected Set<Class<?>> classes = new HashSet<>();

    public ResteasyIAMShieldApplication() {
        classes.add(RealmsResource.class);
        if (Profile.isFeatureEnabled(Profile.Feature.ADMIN_API)) {
            classes.add(AdminRoot.class);
        }
        classes.add(ThemeResource.class);
        classes.add(InvalidQueryParameterFilter.class);
        classes.add(IAMShieldSecurityHeadersFilter.class);
        classes.add(IAMShieldErrorHandler.class);
        classes.add(KcUnrecognizedPropertyExceptionHandler.class);
        classes.add(IAMShieldMismatchedInputExceptionHandler.class);

        singletons.add(new ObjectMapperResolver());
        classes.add(WelcomeResource.class);
        classes.add(ServerMetadataResource.class);

        if (MultiSiteUtils.isMultiSiteEnabled()) {
            // If we are running in multi-site mode, we need to add a resource which to expose
            // an endpoint for the load balancer to gather information whether this site should receive requests or not.
            classes.add(LoadBalancerResource.class);
        }
    }

    @Override
    public Set<Class<?>> getClasses() {
        return classes;
    }

    @Override
    public Set<Object> getSingletons() {
        return singletons;
    }

    @Override
    protected IAMShieldSessionFactory createSessionFactory() {
        ResteasyIAMShieldSessionFactory factory = new ResteasyIAMShieldSessionFactory();
        factory.init();
        return factory;
    }

    @Override
    protected void createTemporaryAdmin(IAMShieldSession session) {
        // do nothing
    }

}
