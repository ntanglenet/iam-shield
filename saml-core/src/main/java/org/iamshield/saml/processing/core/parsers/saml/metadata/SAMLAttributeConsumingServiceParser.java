package org.iamshield.saml.processing.core.parsers.saml.metadata;

import org.iamshield.dom.saml.v2.metadata.AttributeConsumingServiceType;
import org.iamshield.dom.saml.v2.metadata.LocalizedNameType;
import org.iamshield.saml.common.exceptions.ParsingException;
import org.iamshield.saml.common.util.StaxParserUtil;

import javax.xml.stream.XMLEventReader;
import javax.xml.stream.events.StartElement;

import static org.iamshield.saml.processing.core.parsers.saml.metadata.SAMLMetadataQNames.ATTR_LANG;


/**
 * @author mhajas
 */
public class SAMLAttributeConsumingServiceParser extends AbstractStaxSamlMetadataParser<AttributeConsumingServiceType> {

    private static final SAMLAttributeConsumingServiceParser INSTANCE = new SAMLAttributeConsumingServiceParser();

    public SAMLAttributeConsumingServiceParser() {
        super(SAMLMetadataQNames.ATTRIBUTE_CONSUMING_SERVICE);
    }

    public static SAMLAttributeConsumingServiceParser getInstance() {
        return INSTANCE;
    }

    @Override
    protected AttributeConsumingServiceType instantiateElement(XMLEventReader xmlEventReader, StartElement element) throws ParsingException {
        int index = Integer.parseInt(StaxParserUtil.getRequiredAttributeValue(element, SAMLMetadataQNames.ATTR_INDEX));

        AttributeConsumingServiceType service = new AttributeConsumingServiceType(index);
        service.setIsDefault(StaxParserUtil.getBooleanAttributeValue(element, SAMLMetadataQNames.ATTR_IS_DEFAULT));

        return service;
    }

    @Override
    protected void processSubElement(XMLEventReader xmlEventReader, AttributeConsumingServiceType target, SAMLMetadataQNames element, StartElement elementDetail) throws ParsingException {
        switch (element) {
            case SERVICE_NAME:
                LocalizedNameType serviceName = new LocalizedNameType(StaxParserUtil.getAttributeValue(elementDetail, ATTR_LANG));
                StaxParserUtil.advance(xmlEventReader);
                serviceName.setValue(StaxParserUtil.getElementText(xmlEventReader));
                target.addServiceName(serviceName);
                break;

            case SERVICE_DESCRIPTION:
                LocalizedNameType serviceDescription = new LocalizedNameType(StaxParserUtil.getAttributeValue(elementDetail, ATTR_LANG));
                StaxParserUtil.advance(xmlEventReader);
                serviceDescription.setValue(StaxParserUtil.getElementText(xmlEventReader));
                target.addServiceDescription(serviceDescription);
                break;

            case REQUESTED_ATTRIBUTE:
                target.addRequestedAttribute(SAMLRequestedAttributeParser.getInstance().parse(xmlEventReader));
                break;

            default:
                throw LOGGER.parserUnknownTag(StaxParserUtil.getElementName(elementDetail), elementDetail.getLocation());
        }
    }
}
