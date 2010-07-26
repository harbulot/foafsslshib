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
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Collections;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import net.java.dev.sommer.foafssl.principals.FoafSslPrincipal;

import org.apache.velocity.app.VelocityEngine;
import org.apache.velocity.runtime.RuntimeConstants;
import org.opensaml.common.SAMLObject;
import org.opensaml.common.binding.BasicSAMLMessageContext;
import org.opensaml.common.binding.SAMLMessageContext;
import org.opensaml.saml1.binding.encoding.HTTPPostEncoder;
import org.opensaml.saml1.core.Response;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.ws.transport.http.HttpServletRequestAdapter;
import org.opensaml.ws.transport.http.HttpServletResponseAdapter;

import uk.ac.manchester.rcs.foafssl.saml.common.Saml1AuthnResponseBuilder;

/**
 * @author Bruno Harbulot (Bruno.Harbulot@manchester.ac.uk)
 * 
 */
@SuppressWarnings("serial")
public class ShibbolethSaml1IdpServlet extends AbstractShibbolethIdpServlet {
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        Collection<? extends FoafSslPrincipal> verifiedWebIDs = null;

        /*
         * Verifies the certificate passed in the request.
         */
        X509Certificate[] certificates = (X509Certificate[]) request
                .getAttribute("javax.servlet.request.X509Certificate");
        if (certificates != null) {
            X509Certificate foafSslCertificate = certificates[0];
            try {
                verifiedWebIDs = FOAF_SSL_VERIFIER.verifyFoafSslCertificate(foafSslCertificate);
            } catch (Exception e) {
                throw new RuntimeException("Certificate verification failed.", e);
            }
        }

        String shire = request.getParameter("shire");

        if ((verifiedWebIDs != null) && (verifiedWebIDs.size() > 0)) {
            if ((shire != null) && (shire.length() > 0)) {
                /*
                 * Reads the SAML request and generates the SAML response.
                 */
                BasicSAMLMessageContext<SAMLObject, Response, SAMLObject> msgContext = new BasicSAMLMessageContext<SAMLObject, Response, SAMLObject>();
                msgContext.setInboundMessageTransport(new HttpServletRequestAdapter(request));

                try {
                    final String consumerServiceUrl = shire;

                    URI webId = verifiedWebIDs.iterator().next().getUri();

                    Saml1AuthnResponseBuilder samlAuthnResponseBuilder = Saml1AuthnResponseBuilder
                            .getInstance();
                    samlAuthnResponseBuilder.clear();
                    samlAuthnResponseBuilder.setIssuerId(issuerName);
                    samlAuthnResponseBuilder.setSubjectId(webId.toASCIIString());
                    samlAuthnResponseBuilder.setConsumerIds(Collections.singletonList(URI
                            .create(consumerServiceUrl)));
                    Response samlResponse = samlAuthnResponseBuilder
                            .buildSubjectAuthenticatedAssertion(signingCredential, keyName);

                    msgContext.setOutboundMessageTransport(new HttpServletResponseAdapter(response,
                            false));
                    msgContext.setOutboundSAMLMessage(samlResponse);
                    msgContext.setOutboundSAMLMessageSigningCredential(signingCredential);
                    msgContext.setRelayState(request.getParameter("target"));

                    VelocityEngine velocityEngine = new VelocityEngine();
                    velocityEngine.setProperty(RuntimeConstants.ENCODING_DEFAULT, "UTF-8");
                    velocityEngine.setProperty(RuntimeConstants.OUTPUT_ENCODING, "UTF-8");
                    velocityEngine.setProperty(RuntimeConstants.RESOURCE_LOADER, "classpath");
                    velocityEngine.setProperty("classpath.resource.loader.class",
                            "org.apache.velocity.runtime.resource.loader.ClasspathResourceLoader");
                    velocityEngine.init();

                    HTTPPostEncoder httpEncoder = new HTTPPostEncoder(velocityEngine,
                            "templates/saml1-post-binding.vm") {
                        @SuppressWarnings("unchecked")
                        @Override
                        protected String getEndpointURL(SAMLMessageContext messageContext)
                                throws MessageEncodingException {
                            return consumerServiceUrl;
                        }
                    };

                    httpEncoder.encode(msgContext);
                } catch (MessageEncodingException e) {
                    throw new RuntimeException("Error when encoding the response.", e);
                } catch (Exception e) {
                    throw new RuntimeException("Error when encoding the response.", e);
                }

            } else {
                response.getWriter().print(verifiedWebIDs.iterator().next().getName());
                return;
            }
        } else {
            response.getWriter().print("No Verified WebID found.");
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        }
    }
}
