package org.iamshield.saml.processing.core.parsers.saml.metadata;

import org.iamshield.dom.saml.v2.metadata.SSODescriptorType;
import org.iamshield.saml.common.exceptions.ParsingException;
import org.iamshield.saml.common.util.StaxParserUtil;

import javax.xml.stream.XMLEventReader;
import javax.xml.stream.events.StartElement;

/**
 * @author mhajas
 */
public abstract class SAMLSSODescriptorTypeParser<T extends SSODescriptorType> extends SAMLRoleDecriptorTypeParser<T> {

    public SAMLSSODescriptorTypeParser(SAMLMetadataQNames expectedStartElement) {
        super(expectedStartElement);
    }

    @Override
    protected void processSubElement(XMLEventReader xmlEventReader, T target, SAMLMetadataQNames element, StartElement elementDetail) throws ParsingException {
        switch (element) {
            case ARTIFACT_RESOLUTION_SERVICE:
                target.addArtifactResolutionService(SAMLArtifactResolutionServiceParser.getInstance().parse(xmlEventReader));
                break;

            case SINGLE_LOGOUT_SERVICE:
                target.addSingleLogoutService(SAMLSingleLogoutServiceParser.getInstance().parse(xmlEventReader));
                break;

            case MANAGE_NAMEID_SERVICE:
                target.addSingleLogoutService(SAMLManageNameIDServiceParser.getInstance().parse(xmlEventReader));
                break;

            case NAMEID_FORMAT:
                StaxParserUtil.advance(xmlEventReader);
                target.addNameIDFormat(StaxParserUtil.getElementText(xmlEventReader));
                break;

            default:
                super.processSubElement(xmlEventReader, target, element, elementDetail);
        }
    }
}
