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
package uk.ac.manchester.rcs.foafssl.idp;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Collections;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.opensaml.common.SAMLObject;
import org.opensaml.common.binding.BasicSAMLMessageContext;
import org.opensaml.saml1.binding.decoding.HTTPSOAP11Decoder;
import org.opensaml.saml1.binding.encoding.HTTPSOAP11Encoder;
import org.opensaml.saml1.core.AttributeQuery;
import org.opensaml.saml1.core.Request;
import org.opensaml.saml1.core.Response;
import org.opensaml.ws.message.decoder.MessageDecodingException;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.ws.transport.http.HttpServletRequestAdapter;
import org.opensaml.ws.transport.http.HttpServletResponseAdapter;
import org.opensaml.xml.security.SecurityException;

import uk.ac.manchester.rcs.foafssl.saml.common.AttributeContainer;
import uk.ac.manchester.rcs.foafssl.saml.common.Saml1AuthnResponseBuilder;

/**
 * @author Bruno Harbulot (Bruno.Harbulot@manchester.ac.uk)
 * 
 */
@SuppressWarnings("serial")
public class ShibbolethAttributeServiceSaml1SoapServlet extends
        AbstractShibbolethAttributeServiceServlet {
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        try {
            BasicSAMLMessageContext<Request, Response, SAMLObject> msgContext = new BasicSAMLMessageContext<Request, Response, SAMLObject>();
            msgContext.setInboundMessageTransport(new HttpServletRequestAdapter(request));

            HTTPSOAP11Decoder decoder = new HTTPSOAP11Decoder(null);
            decoder.decode(msgContext);

            Request samlRequest = (Request) msgContext.getInboundSAMLMessage();
            AttributeQuery attributeQuery = samlRequest.getAttributeQuery();

            final String consumerServiceUrl = attributeQuery.getResource();
            URI webId = new URI(attributeQuery.getSubject().getNameIdentifier().getNameIdentifier());

            Saml1AuthnResponseBuilder samlAuthnResponseBuilder = Saml1AuthnResponseBuilder
                    .getInstance();
            samlAuthnResponseBuilder.clear();
            samlAuthnResponseBuilder.setIssuerId(issuerName);
            samlAuthnResponseBuilder.setSubjectId(webId.toASCIIString());
            samlAuthnResponseBuilder.setConsumerIds(Collections.singletonList(URI
                    .create(consumerServiceUrl)));
            ArrayList<AttributeContainer> attributeContainers = new ArrayList<AttributeContainer>();
            attributeContainers.add(new AttributeContainer(
                    "urn:mace:dir:attribute-def:eduPersonPrincipalName", webId.toASCIIString()));
            samlAuthnResponseBuilder.setAttributeContainers(attributeContainers);
            Response samlResponse = samlAuthnResponseBuilder.buildSubjectAuthenticatedAssertion(
                    signingCredential, keyName);

            msgContext.setOutboundMessageTransport(new HttpServletResponseAdapter(response, false));
            msgContext.setOutboundSAMLMessage(samlResponse);
            msgContext.setOutboundSAMLMessageSigningCredential(signingCredential);

            HTTPSOAP11Encoder encoder = new HTTPSOAP11Encoder();
            encoder.encode(msgContext);
        } catch (MessageDecodingException e) {
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
        } catch (SecurityException e) {
            response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
        } catch (URISyntaxException e) {
            response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (MessageEncodingException e) {
            response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }
}
