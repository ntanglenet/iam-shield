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

package org.iamshield.adapters.saml.config.parsers;

import org.iamshield.adapters.saml.config.IDP.HttpClientConfig;
import org.iamshield.saml.common.exceptions.ParsingException;
import org.iamshield.saml.common.util.StaxParserUtil;

import javax.xml.stream.XMLEventReader;
import javax.xml.stream.events.StartElement;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
public class HttpClientParser extends AbstractIAMShieldSamlAdapterV1Parser<HttpClientConfig> {

    private static final HttpClientParser INSTANCE = new HttpClientParser();

    private HttpClientParser() {
        super(IAMShieldSamlAdapterV1QNames.HTTP_CLIENT);
    }

    public static HttpClientParser getInstance() {
        return INSTANCE;
    }

    @Override
    protected HttpClientConfig instantiateElement(XMLEventReader xmlEventReader, StartElement element) throws ParsingException {
        final HttpClientConfig config = new HttpClientConfig();

        final Boolean allowAnyHostname = StaxParserUtil.getBooleanAttributeValueRP(element, IAMShieldSamlAdapterV1QNames.ATTR_ALLOW_ANY_HOSTNAME);
        config.setAllowAnyHostname(allowAnyHostname == null ? false : allowAnyHostname);
        config.setClientKeystore(StaxParserUtil.getAttributeValueRP(element, IAMShieldSamlAdapterV1QNames.ATTR_CLIENT_KEYSTORE));
        config.setClientKeystorePassword(StaxParserUtil.getAttributeValueRP(element, IAMShieldSamlAdapterV1QNames.ATTR_CLIENT_KEYSTORE_PASSWORD));
        final Integer connPoolSize = StaxParserUtil.getIntegerAttributeValueRP(element, IAMShieldSamlAdapterV1QNames.ATTR_CONNECTION_POOL_SIZE);
        config.setConnectionPoolSize(connPoolSize == null ? 0 : connPoolSize);
        final Boolean disableTrustManager = StaxParserUtil.getBooleanAttributeValueRP(element, IAMShieldSamlAdapterV1QNames.ATTR_DISABLE_TRUST_MANAGER);
        config.setDisableTrustManager(disableTrustManager == null ? false : disableTrustManager);
        config.setProxyUrl(StaxParserUtil.getAttributeValueRP(element, IAMShieldSamlAdapterV1QNames.ATTR_PROXY_URL));
        config.setTruststore(StaxParserUtil.getAttributeValueRP(element, IAMShieldSamlAdapterV1QNames.ATTR_TRUSTSTORE));
        config.setTruststorePassword(StaxParserUtil.getAttributeValueRP(element, IAMShieldSamlAdapterV1QNames.ATTR_TRUSTSTORE_PASSWORD));

        final Long socketTimeout = StaxParserUtil.getLongAttributeValueRP(element, IAMShieldSamlAdapterV1QNames.ATTR_SOCKET_TIMEOUT);
        config.setSocketTimeout(socketTimeout == null ? -1 : socketTimeout);
        final Long connectionTimeout = StaxParserUtil.getLongAttributeValueRP(element, IAMShieldSamlAdapterV1QNames.ATTR_CONNECTION_TIMEOUT);
        config.setConnectionTimeout(connectionTimeout == null ? -1 : connectionTimeout);
        final Long connectionTTL = StaxParserUtil.getLongAttributeValueRP(element, IAMShieldSamlAdapterV1QNames.ATTR_CONNECTION_TTL);
        config.setConnectionTTL(connectionTTL == null ? -1 : connectionTTL);

        return config;
    }

    @Override
    protected void processSubElement(XMLEventReader xmlEventReader, HttpClientConfig target, IAMShieldSamlAdapterV1QNames element, StartElement elementDetail) throws ParsingException {
    }
}
