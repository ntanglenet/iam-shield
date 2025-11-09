/*
 * Copyright 2016 Red Hat Inc. and/or its affiliates and other contributors
 * as indicated by the @author tags. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */

package org.iamshield.partialimport;

import org.iamshield.models.GroupModel;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.RealmModel;
import org.iamshield.models.utils.IAMShieldModelUtils;
import org.iamshield.models.utils.RepresentationToModel;
import org.iamshield.representations.idm.GroupRepresentation;
import org.iamshield.representations.idm.PartialImportRepresentation;

import java.util.List;

/**
 * Partial import handler for Groups.
 *
 * @author Stan Silvert ssilvert@redhat.com (C) 2016 Red Hat Inc.
 */
public class GroupsPartialImport extends AbstractPartialImport<GroupRepresentation> {

    @Override
    public List<GroupRepresentation> getRepList(PartialImportRepresentation partialImportRep) {
        return partialImportRep.getGroups();
    }

    @Override
    public String getName(GroupRepresentation group) {
        return group.getName();
    }

    private GroupModel findGroupModel(IAMShieldSession session, RealmModel realm, GroupRepresentation groupRep) {
        return IAMShieldModelUtils.findGroupByPath(session, realm, groupRep.getPath());
    }

    @Override
    public String getModelId(RealmModel realm, IAMShieldSession session, GroupRepresentation groupRep) {
        return findGroupModel(session, realm, groupRep).getId();
    }

    @Override
    public boolean exists(RealmModel realm, IAMShieldSession session, GroupRepresentation groupRep) {
        return findGroupModel(session, realm, groupRep) != null;
    }

    @Override
    public String existsMessage(RealmModel realm, GroupRepresentation groupRep) {
        return "Group '" + groupRep.getPath() + "' already exists";
    }

    @Override
    public ResourceType getResourceType() {
        return ResourceType.GROUP;
    }

    @Override
    public void remove(RealmModel realm, IAMShieldSession session, GroupRepresentation groupRep) {
        GroupModel group = realm.getGroupById(getModelId(realm, session, groupRep));
        realm.removeGroup(group);
    }

    @Override
    public void create(RealmModel realm, IAMShieldSession session, GroupRepresentation groupRep) {
        RepresentationToModel.importGroup(realm, null, groupRep);
    }

}
