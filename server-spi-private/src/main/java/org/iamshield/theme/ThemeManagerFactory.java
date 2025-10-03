package org.iamshield.theme;

import org.iamshield.models.ThemeManager;
import org.iamshield.provider.ProviderFactory;

/**
 */
public interface ThemeManagerFactory extends ProviderFactory<ThemeManager> {
  void clearCache();
}
