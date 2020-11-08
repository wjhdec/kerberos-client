package pers.wjh.krb.client;

import org.apache.http.HttpHost;
import org.apache.http.HttpRequest;
import org.apache.http.auth.AuthSchemeProvider;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.Credentials;
import org.apache.http.client.config.AuthSchemes;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.config.Lookup;
import org.apache.http.config.RegistryBuilder;
import org.apache.http.conn.ClientConnectionManager;
import org.apache.http.impl.client.BasicCredentialsProvider;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.params.HttpParams;
import org.apache.http.protocol.HttpContext;

import javax.security.auth.Subject;
import javax.security.auth.kerberos.KerberosPrincipal;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;
import java.io.File;
import java.io.IOException;
import java.security.Principal;
import java.security.PrivilegedAction;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Set;

/**
 * KerberosHttpClient
 *
 * @since 2020/11/8
 */
public class KerberosHttpClient extends CloseableHttpClient {
    private final String keyTabPath;
    private final String principal;

    private final CloseableHttpClient httpClient;

    public KerberosHttpClient(String krbConfPath, String keyTabPath, String principal){
        if(krbConfPath == null || !new File(krbConfPath).exists()){
            throw new IllegalArgumentException("The configuration file of krb5 must be set");
        }
        httpClient = buildHttpClient();
        System.setProperty("java.security.krb5.conf", krbConfPath);
        this.keyTabPath = keyTabPath;
        this.principal = principal;
    }

    @Override
    protected CloseableHttpResponse doExecute(HttpHost target, HttpRequest request, HttpContext context)  {
        KerberosLoginConfig loginConfig = new KerberosLoginConfig(keyTabPath, principal, new HashMap<>(16));
        Set<Principal> principals = new HashSet<>();
        principals.add(new KerberosPrincipal(principal));
        Subject sub = new Subject(false, principals, new HashSet<>(), new HashSet<>());
        try{
            LoginContext lc = new LoginContext("", sub, null, loginConfig);
            lc.login();
            Subject serviceSubject = lc.getSubject();
            return Subject.doAs(serviceSubject, (PrivilegedAction<CloseableHttpResponse>) () ->{
                try {
                    return httpClient.execute(target, request);
                } catch (IOException e) {
                    throw new IllegalArgumentException("Validation error", e);
                }
            });
        }catch (LoginException e){
            throw new IllegalArgumentException("Validation error", e);
        }
    }

    @Override
    public void close() throws IOException {
        if(httpClient != null){
            httpClient.close();
        }
    }

    @Override
    @Deprecated
    public HttpParams getParams() {
        return null;
    }

    @Override
    @Deprecated
    public ClientConnectionManager getConnectionManager() {
        return null;
    }

    private static class NullCredentials implements Credentials {
        @Override
        public Principal getUserPrincipal() {
            return null;
        }
        @Override
        public String getPassword() {
            return null;
        }
    }

    private final Credentials CREDENTIALS = new NullCredentials();
    private CloseableHttpClient buildHttpClient() {
        HttpClientBuilder builder = HttpClientBuilder.create();
        Lookup<AuthSchemeProvider> authSchemeRegistry = RegistryBuilder.<AuthSchemeProvider>create()
                .register(AuthSchemes.SPNEGO, new CustomSPNegoSchemeFactory(true, false)).build();
        builder.setDefaultAuthSchemeRegistry(authSchemeRegistry);
        BasicCredentialsProvider credentialsProvider = new BasicCredentialsProvider();
        credentialsProvider.setCredentials(new AuthScope(null, -1, null), CREDENTIALS);
        builder.setDefaultCredentialsProvider(credentialsProvider);
        return builder.build();
    }
}
