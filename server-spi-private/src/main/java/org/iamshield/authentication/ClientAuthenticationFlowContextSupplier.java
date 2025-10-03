package org.iamshield.authentication;

public interface ClientAuthenticationFlowContextSupplier<T> {

    T get(ClientAuthenticationFlowContext context) throws Exception;

}
