package org.iamshield.services.resource;

import org.iamshield.provider.Provider;
import org.iamshield.theme.Theme;

import java.io.IOException;

/**
 * <p>A {@link AccountResourceProvider} creates JAX-RS resource instances for the Account endpoints, allowing
 * an implementor to override the behavior of the entire Account console.
 */
public interface AccountResourceProvider extends Provider {
  /** Returns a JAX-RS resource instance. */
  Object getResource();
}
