package org.iamshield.theme.freemarker;

import org.iamshield.provider.Provider;
import org.iamshield.theme.FreeMarkerException;
import org.iamshield.theme.Theme;

public interface FreeMarkerProvider extends Provider {

    public String processTemplate(Object data, String templateName, Theme theme) throws FreeMarkerException;

}
