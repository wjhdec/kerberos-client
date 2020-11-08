package pers.wjh.krb.client;

import org.apache.http.auth.AuthScheme;
import org.apache.http.auth.Credentials;
import org.apache.http.auth.KerberosCredentials;
import org.apache.http.impl.auth.SPNegoScheme;
import org.apache.http.impl.auth.SPNegoSchemeFactory;
import org.apache.http.protocol.HttpContext;
import org.ietf.jgss.*;

class CustomSPNegoSchemeFactory  extends SPNegoSchemeFactory  {
    public CustomSPNegoSchemeFactory(final boolean stripPort, final boolean useCanonicalHostname) {
        super(stripPort, useCanonicalHostname);
    }

    @Override
    public AuthScheme create(final HttpContext context) {
        return new SPNegoScheme(){
            @Override
            protected byte[] generateGSSToken(byte[] input, Oid oid, String authServer, Credentials credentials) throws GSSException {
                byte[] inputBuff = input;
                if (inputBuff == null) {
                    inputBuff = new byte[0];
                }
                final GSSManager manager = getManager();

                GSSName gssName = manager.createName("HTTP@" + authServer, GSSName.NT_HOSTBASED_SERVICE);

                final GSSCredential gssCredential;
                if (credentials instanceof KerberosCredentials) {
                    gssCredential = ((KerberosCredentials) credentials).getGSSCredential();
                } else {
                    gssCredential = null;
                }

                final GSSContext gssContext = manager.createContext(
                        gssName.canonicalize(oid), oid, gssCredential, GSSContext.DEFAULT_LIFETIME);
                gssContext.requestMutualAuth(true);
                gssContext.requestCredDeleg(true);
                return gssContext.initSecContext(inputBuff, 0, inputBuff.length);
            }
        };
    }
}
