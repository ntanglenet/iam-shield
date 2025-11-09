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

package org.iamshield.theme;

import org.iamshield.Config;
import org.iamshield.common.Profile;
import org.iamshield.provider.Provider;

/**
 * @author <a href="mailto:sthorger@redhat.com">Stian Thorgersen</a>
 */
public interface ThemeSelectorProvider extends Provider {

    String DEFAULT = "iamshield";
    String DEFAULT_V2 = "iamshield.v2";
    String DEFAULT_V3 = "iamshield.v3";

    /**
     * Return the theme name to use for the specified type
     *
     * @param type
     * @return
     */
    String getThemeName(Theme.Type type);

    default String getDefaultThemeName(Theme.Type type) {
        String name = Config.scope("theme").get("default");
        if (name != null && !name.isEmpty()) {
            return name;
        }

        if ((type == Theme.Type.ACCOUNT) && Profile.isFeatureEnabled(Profile.Feature.ACCOUNT_V3)) {
            return DEFAULT_V3;
        }

        if ((type == Theme.Type.ADMIN) && Profile.isFeatureEnabled(Profile.Feature.ADMIN_V2)) {
            return DEFAULT_V2;
        }

        if ((type == Theme.Type.LOGIN) && Profile.isFeatureEnabled(Profile.Feature.LOGIN_V2)) {
            return DEFAULT_V2;
        }

        return DEFAULT;
    }

}
