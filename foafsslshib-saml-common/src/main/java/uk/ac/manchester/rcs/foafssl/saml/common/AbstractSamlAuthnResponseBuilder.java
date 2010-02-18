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
import java.util.List;

import org.joda.time.DateTime;

/**
 * This class builds a SAML assertion after a URI has been authenticated
 * successfully.
 * 
 * @author Bruno Harbulot (Bruno.Harbulot@manchester.ac.uk)
 * 
 */
public abstract class AbstractSamlAuthnResponseBuilder {
    private DateTime assertionInstant;
    private Collection<AttributeContainer> attributeContainers;
    private List<URI> audienceUris;
    private DateTime authenticationInstant;
    private String confirmationMethod;
    private List<URI> consumerIds;
    private String issuerId;
    private DateTime notAfterCondition;
    private DateTime notBeforeCondition;
    private DateTime responseIssueInstant;
    private String subjectId;

    public void clear() {
        issuerId = null;
        consumerIds = null;
        subjectId = null;
        confirmationMethod = null;
        authenticationInstant = null;
        assertionInstant = null;
        audienceUris = null;
        notBeforeCondition = null;
        notAfterCondition = null;
        responseIssueInstant = null;
        attributeContainers = null;
    }

    public DateTime getAssertionInstant() {
        if (this.assertionInstant == null) {
            return new DateTime();
        } else {
            return this.assertionInstant;
        }
    }

    public Collection<AttributeContainer> getAttributeContainers() {
        return this.attributeContainers;
    }

    public List<URI> getAudienceUris() {
        return this.audienceUris;
    }

    public DateTime getAuthenticationInstant() {
        if (this.authenticationInstant != null) {
            return this.authenticationInstant;
        } else {
            return getAssertionInstant();
        }
    }

    public String getAuthenticationMethod() {
        return "http://esw.w3.org/topic/foaf+ssl";
    }

    public String getConfirmationMethod() {
        if (this.confirmationMethod != null) {
            return this.confirmationMethod;
        } else {
            return "urn:oasis:names:tc:SAML:1.0:cm:bearer";
        }
    }

    public List<URI> getConsumerIds() {
        return this.consumerIds;
    }

    public String getIssuerId() {
        return this.issuerId;
    }

    public DateTime getNotAfterCondition() {
        if (this.notAfterCondition != null) {
            return this.notAfterCondition;
        } else {
            return getNotBeforeCondition().plusHours(1);
        }
    }

    public DateTime getNotBeforeCondition() {
        if (this.notBeforeCondition != null) {
            return this.notBeforeCondition;
        } else {
            return getAssertionInstant();
        }
    }

    public DateTime getResponseIssueInstant() {
        if (this.responseIssueInstant != null) {
            return this.responseIssueInstant;
        } else {
            return getAssertionInstant();
        }
    }

    public String getSubjectFormat() {
        return "http://foafssl.org/foafsslid";
    }

    public String getSubjectId() {
        return this.subjectId;
    }

    public void setAssertionInstant(DateTime assertionInstant) {
        this.assertionInstant = assertionInstant;
    }

    public void setAttributeContainers(Collection<AttributeContainer> attributeContainers) {
        this.attributeContainers = attributeContainers;
    }

    public void setAudienceUris(List<URI> audienceUris) {
        this.audienceUris = audienceUris;
    }

    public void setAuthenticationInstant(DateTime authenticationInstant) {
        this.authenticationInstant = authenticationInstant;
    }

    public void setConfirmationMethod(String confirmationMethod) {
        this.confirmationMethod = confirmationMethod;
    }

    public void setConsumerIds(List<URI> consumerIds) {
        this.consumerIds = consumerIds;
    }

    public void setIssuerId(String issuerId) {
        this.issuerId = issuerId;
    }

    public void setNotAfterCondition(DateTime notAfterCondition) {
        this.notAfterCondition = notAfterCondition;
    }

    public void setNotBeforeCondition(DateTime notBeforeCondition) {
        this.notBeforeCondition = notBeforeCondition;
    }

    public void setResponseIssueInstant(DateTime responseIssueInstant) {
        this.responseIssueInstant = responseIssueInstant;
    }

    public void setSubjectId(String subjectId) {
        this.subjectId = subjectId;
    }
}
