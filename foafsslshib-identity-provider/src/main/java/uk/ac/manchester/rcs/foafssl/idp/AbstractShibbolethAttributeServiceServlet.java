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

import java.security.cert.X509Certificate;
import java.util.logging.Level;

import javax.naming.Context;
import javax.naming.InitialContext;
import javax.naming.NameNotFoundException;
import javax.naming.NamingException;
import javax.servlet.ServletException;

import net.java.dev.sommer.foafssl.login.AbstractIdpServlet;

import org.opensaml.xml.security.SecurityHelper;
import org.opensaml.xml.security.credential.Credential;

/**
 * @author Bruno Harbulot (Bruno.Harbulot@manchester.ac.uk)
 * 
 */
@SuppressWarnings("serial")
public abstract class AbstractShibbolethAttributeServiceServlet extends AbstractIdpServlet {
    public final static String SAMLISSUERNAME_JNDI_NAME = "foafsslidp/samlIssuerName";
    public final static String SAMLKEYNAME_JNDI_NAME = "foafsslidp/samlKeyName";

    public final static String ISSUER_NAME_INITPARAM = "issuerName";
    public final static String KEY_NAME_INITPARAM = "keyName";

    protected volatile Credential signingCredential = null;
    protected volatile String issuerName = null;
    protected volatile String keyName = null;

    /**
     * Initialises the servlet: loads the keystore/keys to use to sign the
     * assertions and the issuer name.
     */
    @Override
    public void init() throws ServletException {
        super.init();

        String issuerName = getInitParameter(ISSUER_NAME_INITPARAM);
        String keyName = getInitParameter(KEY_NAME_INITPARAM);

        try {
            Context initCtx = new InitialContext();
            Context ctx = (Context) initCtx.lookup("java:comp/env");
            try {
                try {
                    String jndiIssuerName = (String) ctx.lookup(SAMLISSUERNAME_JNDI_NAME);
                    if (jndiIssuerName != null) {
                        issuerName = jndiIssuerName;
                    }
                } catch (NameNotFoundException e) {
                    LOG.log(Level.FINE, "JNDI name not found", e);
                }

                try {
                    String jndiKeyName = (String) ctx.lookup(SAMLKEYNAME_JNDI_NAME);
                    if (jndiKeyName != null) {
                        keyName = jndiKeyName;
                    }
                } catch (NameNotFoundException e) {
                    LOG.log(Level.FINE, "JNDI name not found", e);
                }
            } finally {
                if (ctx != null) {
                    ctx.close();
                }
                if (initCtx != null) {
                    initCtx.close();
                }
            }
        } catch (NameNotFoundException e) {
            LOG.log(Level.INFO, "Unable to load JNDI context.", e);
        } catch (NamingException e) {
            LOG.log(Level.INFO, "Unable to load JNDI context.", e);
        }

        this.issuerName = issuerName;
        this.keyName = keyName;
        this.signingCredential = SecurityHelper.getSimpleCredential((X509Certificate) certificate,
                privateKey);
    }
}
