/**-----------------------------------------------------------------------
  
Copyright (c) 2010, The University of Manchester, United Kingdom.
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

import javax.xml.namespace.QName;

/**
 * @author Bruno Harbulot (Bruno.Harbulot@manchester.ac.uk)
 * 
 */
public class AttributeContainer {
    public final static String SHIBBOLETH_ATTRIBUTE_NAMESPACE = "urn:mace:shibboleth:1.0:attributeNamespace:uri";

    private final String attributeName;
    private final String attributeNamespace;
    private final QName attributeValueType;
    private final String attributeValue;

    /**
     * @param attributeName
     * @param attributeNamespace
     * @param attributeValueType
     * @param attributeValue
     */
    public AttributeContainer(String attributeName, String attributeNamespace,
            QName attributeValueType, String attributeValue) {
        this.attributeName = attributeName;
        if (attributeNamespace != null) {
            this.attributeNamespace = attributeNamespace;
        } else {
            this.attributeNamespace = SHIBBOLETH_ATTRIBUTE_NAMESPACE;
        }
        this.attributeValueType = attributeValueType;
        this.attributeValue = attributeValue;
    }

    /**
     * @param attributeName
     * @param attributeNamespace
     * @param attributeValue
     */
    public AttributeContainer(String attributeName, String attributeNamespace, String attributeValue) {
        this(attributeName, attributeNamespace, null, attributeValue);
    }

    /**
     * @param attributeName
     * @param attributeValue
     */
    public AttributeContainer(String attributeName, String attributeValue) {
        this(attributeName, null, null, attributeValue);
    }

    public String getAttributeName() {
        return this.attributeName;
    }

    public String getAttributeNamespace() {
        return this.attributeNamespace;
    }

    public QName getAttributeValueType() {
        return this.attributeValueType;
    }

    public String getAttributeValue() {
        return this.attributeValue;
    }
}
