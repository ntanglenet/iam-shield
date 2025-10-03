package org.iamshield.forms.login.freemarker.model;

import java.util.List;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.protocol.oidc.FrontChannelLogoutHandler;

public class FrontChannelLogoutBean {

    private final FrontChannelLogoutHandler logoutInfo;

    public FrontChannelLogoutBean(IAMShieldSession session) {
        logoutInfo = FrontChannelLogoutHandler.current(session);
    }

    public String getLogoutRedirectUri() {
        return logoutInfo.getLogoutRedirectUri();
    }

    public List<FrontChannelLogoutHandler.ClientInfo> getClients() {
        return logoutInfo.getClients();
    }

}
