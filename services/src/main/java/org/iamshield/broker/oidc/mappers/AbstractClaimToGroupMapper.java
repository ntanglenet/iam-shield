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

package org.iamshield.broker.oidc.mappers;

import org.jboss.logging.Logger;
import org.iamshield.broker.provider.BrokeredIdentityContext;
import org.iamshield.broker.provider.ConfigConstants;
import org.iamshield.models.GroupModel;
import org.iamshield.models.IdentityProviderMapperModel;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.RealmModel;
import org.iamshield.models.UserModel;
import org.iamshield.models.utils.IAMShieldModelUtils;

/**
 * @author <a href="mailto:artur.baltabayev@bosch.io">Artur Baltabayev</a>,
 * <a href="mailto:daniel.fesenmeyer@bosch.io">Daniel Fesenmeyer</a>
 */
public abstract class AbstractClaimToGroupMapper extends AbstractClaimMapper {

    private static final Logger LOG = Logger.getLogger(AbstractClaimToGroupMapper.class);


    @Override
    public void importNewUser(IAMShieldSession session, RealmModel realm, UserModel user,
            IdentityProviderMapperModel mapperModel, BrokeredIdentityContext context) {

        GroupModel group = this.getGroup(session, realm, mapperModel);
        if (group == null) {
            return;
        }

        if (applies(mapperModel, context)) {
            user.joinGroup(group);
        }
    }

    @Override
    public void updateBrokeredUser(IAMShieldSession session, RealmModel realm, UserModel user,
            IdentityProviderMapperModel mapperModel, BrokeredIdentityContext context) {

        GroupModel group = this.getGroup(session, realm, mapperModel);
        if (group == null) {
            return;
        }

        String groupId = group.getId();
        if (!context.hasMapperAssignedGroup(groupId)) {
            if (applies(mapperModel, context)) {
                context.addMapperAssignedGroup(groupId);
                user.joinGroup(group);
            } else {
                user.leaveGroup(group);
            }
        }
    }

    /**
     * This method must be implemented by subclasses and they must return {@code true} if their mapping can be applied
     * (i.e. user has the OIDC claim that should be mapped) or {@code false} otherwise.
     *
     * @param mapperModel a reference to the {@link IdentityProviderMapperModel}.
     * @param context a reference to the {@link BrokeredIdentityContext}.
     * @return {@code true} if the mapping can be applied or {@code false} otherwise.*
     */
    protected abstract boolean applies(final IdentityProviderMapperModel mapperModel,
            final BrokeredIdentityContext context);

    private GroupModel getGroup(IAMShieldSession session, final RealmModel realm, final IdentityProviderMapperModel mapperModel) {
        String groupPath = mapperModel.getConfig().get(ConfigConstants.GROUP);
        GroupModel group = IAMShieldModelUtils.findGroupByPath(session, realm, groupPath);

        if (group == null) {
            LOG.warnf("Unable to find group by path '%s' referenced by mapper '%s' on realm '%s'.", groupPath,
                    mapperModel.getName(), realm.getName());
        }

        return group;
    }

}
