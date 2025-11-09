package org.iamshield.theme;

import org.iamshield.Config;
import org.iamshield.models.ClientModel;
import org.iamshield.models.IAMShieldSession;

public class DefaultThemeSelectorProvider implements ThemeSelectorProvider {

    public static final String LOGIN_THEME_KEY = "login_theme";

    private final IAMShieldSession session;

    public DefaultThemeSelectorProvider(IAMShieldSession session) {
        this.session = session;
    }

    @Override
    public String getThemeName(Theme.Type type) {
        String name = null;

        switch (type) {
            case WELCOME:
                name = Config.scope("theme").get("welcomeTheme");
                break;
            case LOGIN:
                ClientModel client = session.getContext().getClient();
                if (client != null) {
                    name = client.getAttribute(LOGIN_THEME_KEY);
                }

                if (name == null || name.isEmpty()) {
                    name = session.getContext().getRealm().getLoginTheme();
                }
                
                break;
            case ACCOUNT:
                name = session.getContext().getRealm().getAccountTheme();
                break;
            case EMAIL:
                name = session.getContext().getRealm().getEmailTheme();
                break;
            case ADMIN:
                name = session.getContext().getRealm().getAdminTheme();
                break;
        }

        if (name == null || name.isEmpty()) {
            name = getDefaultThemeName(type);
        }

        return name;
    }

    @Override
    public void close() {
    }

}

