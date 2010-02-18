/**-----------------------------------------------------------------------
  
Copyright (c) 2009-2010, The University of Manchester, United Kingdom.
All rights reserved.

Redistribution and use in source and binary forms, with or without 
modification, are permitted provided that the following conditions are met:

 * Redistributions of source code must retain the above copyright notice, 
      this list of conditions and the following disclaimer.
 * Redistributions in binary form must reproduce the above copyright 
      notice, this list of conditions and the following disclaimer in the 
      documentation and/or other materials provided with the distribution.
 * Neither the name of the The University of Manchester nor the names of 
      its contributors may be used to endorse or promote products derived 
      from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" 
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE 
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE 
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE 
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR 
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF 
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS 
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN 
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) 
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE 
POSSIBILITY OF SUCH DAMAGE.

  Author........: Bruno Harbulot

-----------------------------------------------------------------------*/
package uk.ac.manchester.rcs.foafssl.saml.common;

import java.net.URI;
import java.util.Collection;
import java.util.UUID;

import javax.xml.namespace.QName;

import org.opensaml.DefaultBootstrap;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.saml1.core.Assertion;
import org.opensaml.saml1.core.Attribute;
import org.opensaml.saml1.core.AttributeStatement;
import org.opensaml.saml1.core.AttributeValue;
import org.opensaml.saml1.core.Audience;
import org.opensaml.saml1.core.AudienceRestrictionCondition;
import org.opensaml.saml1.core.AuthenticationStatement;
import org.opensaml.saml1.core.Conditions;
import org.opensaml.saml1.core.ConfirmationMethod;
import org.opensaml.saml1.core.NameIdentifier;
import org.opensaml.saml1.core.Response;
import org.opensaml.saml1.core.Status;
import org.opensaml.saml1.core.StatusCode;
import org.opensaml.saml1.core.Subject;
import org.opensaml.saml1.core.SubjectConfirmation;
import org.opensaml.xml.Configuration;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.XMLObjectBuilder;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.schema.XSString;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.security.SecurityHelper;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.signature.KeyName;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureException;
import org.opensaml.xml.signature.Signer;

import uk.ac.manchester.rcs.foafssl.saml.common.Saml1AuthnResponseBuilder;

/**
 * This class builds a SAML assertion after a URI has been authenticated
 * successfully.
 * 
 * @author Bruno Harbulot (Bruno.Harbulot@manchester.ac.uk)
 * 
 */
public class Saml1AuthnResponseBuilder extends AbstractSamlAuthnResponseBuilder {
    private static final ThreadLocal<Saml1AuthnResponseBuilder> instances = new ThreadLocal<Saml1AuthnResponseBuilder>();

    public static Saml1AuthnResponseBuilder getInstance() {
        Saml1AuthnResponseBuilder instance = instances.get();
        if (instance == null) {
            instance = new Saml1AuthnResponseBuilder();
            instances.set(instance);
        }
        return instance;
    }

    private final SAMLObjectBuilder<Subject> subjectBuilder;
    private final SAMLObjectBuilder<NameIdentifier> nameIdBuilder;
    private final SAMLObjectBuilder<Assertion> assertionBuilder;
    private final SAMLObjectBuilder<AuthenticationStatement> authStatementBuilder;
    private final SAMLObjectBuilder<Response> responseBuilder;
    private final SAMLObjectBuilder<ConfirmationMethod> confirmationMethodBuilder;
    private final SAMLObjectBuilder<SubjectConfirmation> subjectConfirmationBuilder;
    private final SAMLObjectBuilder<Conditions> conditionsBuilder;
    private final SAMLObjectBuilder<AudienceRestrictionCondition> audienceRestrictionBuilder;
    private final SAMLObjectBuilder<AttributeStatement> attributeStatementBuilder;
    private final SAMLObjectBuilder<Attribute> attributeBuilder;
    private final SAMLObjectBuilder<Audience> audienceBuilder;
    private final SAMLObjectBuilder<Status> statusBuilder;
    private final SAMLObjectBuilder<StatusCode> statusCodeBuilder;
    private final XMLObjectBuilder<Signature> signatureBuilder;
    private final XMLObjectBuilder<KeyName> keynameBuilder;
    private final XMLObjectBuilder<XSString> stringBuilder;

    /**
     * Constructor. Initialiases the various SAML object builders of OpenSAML.
     */
    @SuppressWarnings("unchecked")
    private Saml1AuthnResponseBuilder() {
        XMLObjectBuilderFactory xmlObjectBuilderFactory = Configuration.getBuilderFactory();
        if (xmlObjectBuilderFactory.getBuilders().isEmpty()) {
            try {
                DefaultBootstrap.bootstrap();
            } catch (ConfigurationException e) {
                throw new RuntimeException(e);
            }
            xmlObjectBuilderFactory = Configuration.getBuilderFactory();
        }

        subjectBuilder = (SAMLObjectBuilder<Subject>) xmlObjectBuilderFactory
                .getBuilder(Subject.DEFAULT_ELEMENT_NAME);

        nameIdBuilder = (SAMLObjectBuilder<NameIdentifier>) xmlObjectBuilderFactory
                .getBuilder(NameIdentifier.DEFAULT_ELEMENT_NAME);

        assertionBuilder = (SAMLObjectBuilder<Assertion>) xmlObjectBuilderFactory
                .getBuilder(Assertion.DEFAULT_ELEMENT_NAME);

        authStatementBuilder = (SAMLObjectBuilder<AuthenticationStatement>) xmlObjectBuilderFactory
                .getBuilder(AuthenticationStatement.DEFAULT_ELEMENT_NAME);

        responseBuilder = (SAMLObjectBuilder<Response>) xmlObjectBuilderFactory
                .getBuilder(Response.DEFAULT_ELEMENT_NAME);

        attributeStatementBuilder = (SAMLObjectBuilder<AttributeStatement>) xmlObjectBuilderFactory
                .getBuilder(AttributeStatement.DEFAULT_ELEMENT_NAME);
        attributeBuilder = (SAMLObjectBuilder<Attribute>) xmlObjectBuilderFactory
                .getBuilder(Attribute.DEFAULT_ELEMENT_NAME);

        conditionsBuilder = (SAMLObjectBuilder<Conditions>) xmlObjectBuilderFactory
                .getBuilder(Conditions.DEFAULT_ELEMENT_NAME);

        subjectConfirmationBuilder = (SAMLObjectBuilder<SubjectConfirmation>) xmlObjectBuilderFactory
                .getBuilder(SubjectConfirmation.DEFAULT_ELEMENT_NAME);

        confirmationMethodBuilder = (SAMLObjectBuilder<ConfirmationMethod>) xmlObjectBuilderFactory
                .getBuilder(ConfirmationMethod.DEFAULT_ELEMENT_NAME);

        audienceRestrictionBuilder = (SAMLObjectBuilder<AudienceRestrictionCondition>) xmlObjectBuilderFactory
                .getBuilder(AudienceRestrictionCondition.DEFAULT_ELEMENT_NAME);

        audienceBuilder = (SAMLObjectBuilder<Audience>) xmlObjectBuilderFactory
                .getBuilder(Audience.DEFAULT_ELEMENT_NAME);

        statusBuilder = (SAMLObjectBuilder<Status>) xmlObjectBuilderFactory
                .getBuilder(Status.DEFAULT_ELEMENT_NAME);

        statusCodeBuilder = (SAMLObjectBuilder<StatusCode>) xmlObjectBuilderFactory
                .getBuilder(StatusCode.DEFAULT_ELEMENT_NAME);

        signatureBuilder = (XMLObjectBuilder<Signature>) xmlObjectBuilderFactory
                .getBuilder(Signature.DEFAULT_ELEMENT_NAME);

        keynameBuilder = (XMLObjectBuilder<KeyName>) xmlObjectBuilderFactory
                .getBuilder(KeyName.DEFAULT_ELEMENT_NAME);

        stringBuilder = (XMLObjectBuilder<XSString>) xmlObjectBuilderFactory
                .getBuilder(XSString.TYPE_NAME);
    }

    public Response buildSubjectAuthenticatedAssertion(Credential signingCredential,
            String keyNameValue) {
        NameIdentifier samlNameId = nameIdBuilder.buildObject();
        samlNameId.setFormat(getSubjectFormat());
        samlNameId.setNameIdentifier(getSubjectId());

        ConfirmationMethod samlConfirmationMethod = confirmationMethodBuilder.buildObject();
        samlConfirmationMethod.setConfirmationMethod(getConfirmationMethod());

        SubjectConfirmation samlSubjectConfirmation = subjectConfirmationBuilder.buildObject();
        samlSubjectConfirmation.getConfirmationMethods().add(samlConfirmationMethod);

        Subject samlSubject = subjectBuilder.buildObject();
        samlSubject.setNameIdentifier(samlNameId);
        samlSubject.setSubjectConfirmation(samlSubjectConfirmation);

        AuthenticationStatement samlAuthnStatement = authStatementBuilder.buildObject();
        samlAuthnStatement.setAuthenticationInstant(getAuthenticationInstant());
        samlAuthnStatement.setAuthenticationMethod(getAuthenticationMethod());
        samlAuthnStatement.setSubject(samlSubject);

        Assertion samlAssertion = assertionBuilder.buildObject();
        samlAssertion.getAuthenticationStatements().add(samlAuthnStatement);
        Collection<URI> consumerIds = getConsumerIds();
        if ((consumerIds != null) && (consumerIds.size() > 0)) {
            Conditions samlConditions = conditionsBuilder.buildObject();

            if ((getAudienceUris() != null) && (getAudienceUris().size() > 0)) {
                AudienceRestrictionCondition samlAudienceRestriction = audienceRestrictionBuilder
                        .buildObject();
                for (URI audienceId : getAudienceUris()) {
                    Audience samlAudience = audienceBuilder.buildObject();
                    samlAudience.setUri(audienceId.toASCIIString());
                    samlAudienceRestriction.getAudiences().add(samlAudience);
                }
                samlConditions.getAudienceRestrictionConditions().add(samlAudienceRestriction);
            }
            samlConditions.setNotBefore(getNotBeforeCondition());
            samlConditions.setNotOnOrAfter(getNotAfterCondition());
            samlAssertion.setConditions(samlConditions);
        }
        samlAssertion.setIssuer(getIssuerId());
        samlAssertion.setIssueInstant(getAssertionInstant());
        samlAssertion.setID(UUID.randomUUID().toString());

        Collection<AttributeContainer> attributeContainers = getAttributeContainers();
        if ((attributeContainers != null) && (attributeContainers.size() > 0)) {
            samlNameId = nameIdBuilder.buildObject();
            samlNameId.setFormat(getSubjectFormat());
            samlNameId.setNameIdentifier(getSubjectId());

            samlConfirmationMethod = confirmationMethodBuilder.buildObject();
            samlConfirmationMethod.setConfirmationMethod(getConfirmationMethod());

            samlSubjectConfirmation = subjectConfirmationBuilder.buildObject();
            samlSubjectConfirmation.getConfirmationMethods().add(samlConfirmationMethod);

            samlSubject = subjectBuilder.buildObject();
            samlSubject.setNameIdentifier(samlNameId);
            samlSubject.setSubjectConfirmation(samlSubjectConfirmation);

            AttributeStatement samlAttributeStatement = attributeStatementBuilder.buildObject();
            samlAttributeStatement.setSubject(samlSubject);

            for (AttributeContainer attributeContainer : attributeContainers) {
                Attribute attribute = buildAttribute(attributeContainer);
                samlAttributeStatement.getAttributes().add(attribute);
            }

            samlAssertion.getAttributeStatements().add(samlAttributeStatement);
        }

        Response samlResponse = responseBuilder.buildObject();
        samlResponse.getAssertions().add(samlAssertion);

        StatusCode samlStatusCode = statusCodeBuilder.buildObject();
        samlStatusCode.setValue(StatusCode.SUCCESS);
        Status samlStatus = statusBuilder.buildObject();
        samlStatus.setStatusCode(samlStatusCode);
        samlResponse.setStatus(samlStatus);

        samlResponse.setID(UUID.randomUUID().toString());
        samlResponse.setIssueInstant(getResponseIssueInstant());

        if (signingCredential != null) {
            try {
                Signature signature = signatureBuilder.buildObject(Signature.DEFAULT_ELEMENT_NAME);
                SecurityHelper.prepareSignatureParams(signature, signingCredential, null, null);
                signature.getKeyInfo().getKeyValues().clear();
                if (keyNameValue != null) {
                    KeyName keyname = keynameBuilder.buildObject(KeyName.DEFAULT_ELEMENT_NAME);
                    keyname.setValue(keyNameValue);
                    signature.getKeyInfo().getKeyNames().add(keyname);
                }

                signature.setSigningCredential(signingCredential);
                samlResponse.setSignature(signature);

                Configuration.getMarshallerFactory().getMarshaller(samlResponse).marshall(
                        samlResponse);
                Signer.signObject(signature);
            } catch (SecurityException e) {
                throw new RuntimeException(e);
            } catch (MarshallingException e) {
                throw new RuntimeException(e);
            } catch (SignatureException e) {
                throw new RuntimeException(e);
            }
        }

        return samlResponse;
    }

    protected Attribute buildAttribute(AttributeContainer attributeContainer) {
        Attribute samlAttribute = attributeBuilder.buildObject();
        samlAttribute.setAttributeName(attributeContainer.getAttributeName());
        samlAttribute.setAttributeNamespace(attributeContainer.getAttributeNamespace());

        QName attributeValueType = attributeContainer.getAttributeValueType();
        if (attributeValueType == null) {
            attributeValueType = XSString.TYPE_NAME;
        }
        XSString samlAttributeValue = (XSString) stringBuilder.buildObject(
                AttributeValue.DEFAULT_ELEMENT_NAME, attributeValueType);
        samlAttributeValue.setValue(attributeContainer.getAttributeValue());

        samlAttribute.getAttributeValues().add(samlAttributeValue);

        return samlAttribute;
    }
}
