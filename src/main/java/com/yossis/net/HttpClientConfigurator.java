package com.yossis.net;

import org.apache.http.HttpException;
import org.apache.http.HttpHost;
import org.apache.http.HttpRequest;
import org.apache.http.HttpRequestInterceptor;
import org.apache.http.auth.*;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.client.config.AuthSchemes;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.protocol.HttpClientContext;
import org.apache.http.conn.routing.HttpRoute;
import org.apache.http.conn.routing.RouteInfo;
import org.apache.http.conn.socket.LayeredConnectionSocketFactory;
import org.apache.http.conn.ssl.SSLSocketFactory;
import org.apache.http.impl.auth.BasicScheme;
import org.apache.http.impl.client.*;
import org.apache.http.impl.conn.DefaultRoutePlanner;
import org.apache.http.impl.conn.DefaultSchemePortResolver;
import org.apache.http.protocol.HttpContext;

import javax.net.ssl.SSLContext;
import java.io.*;
import java.net.*;
import java.security.*;
import java.util.Arrays;
import java.util.List;

/**
 * Created by freds on 9/19/14.
 */
public class HttpClientConfigurator {
    private HttpClientBuilder builder = HttpClients.custom();
    private RequestConfig.Builder config = RequestConfig.custom();
    private String host;
    private BasicCredentialsProvider credsProvider;
    protected String DEFAULT_STORE_TYPE="JKS";
    public HttpClientConfigurator() {
        builder.setUserAgent("Artifactory/3.0-test.connect-1");
        credsProvider = new BasicCredentialsProvider();
        builder.disableCookieManagement();
        //builder.disableContentCompression();
    }

    public CloseableHttpClient getClient() {
        if (hasCredentials()) {
            builder.setDefaultCredentialsProvider(credsProvider);
        }
        return builder.setDefaultRequestConfig(config.build()).build();
    }

    public HttpClientConfigurator setupKeyStore(String keyStorePath, String keyStorePassword )
    {
        //SSLContext mySSLctx= new SSLContext();
        //KeyStore keyStore = KeyStore.Builder.
        //LayeredConnectionSocketFactory mySSLSocketFact = new SSLSocketFactory();
        //TODO: Figure out how to build an SSL socket factory with the trust store
        return this;
    }


    public HttpClientConfigurator setupTrustStore(String trustStorePath, String trustStorePassword)
    {
        try {
            //for the trust store, probably no need to support anything other than JKS.
            KeyStore trustStore = getTrustStore(trustStorePath, trustStorePassword, null);
            LayeredConnectionSocketFactory mySSLSocketFact = new SSLSocketFactory(trustStore);
            builder.setSSLSocketFactory(mySSLSocketFact);
        } catch (IOException ioe) {
            Log.error("setupTrustStore error: ", ioe);
        } catch (NoSuchAlgorithmException nsae)
        {
            Log.error("setupTrustStore error: No Such Algorithm Exception: ", nsae);
        } catch (KeyManagementException kme)
        {
            Log.error("setupTrustStore error: Key Management Exception: ", kme);
        } catch (KeyStoreException kse)
        {
            Log.error("setupTrustStore error: Key Store Exception: ", kse);
        } catch (UnrecoverableKeyException urke)
        {
            Log.error("setupTrustStore error: Key Store Exception: ", urke);
        }
        return this;
    }

    protected KeyStore getTrustStore(String trustStorePath, String trustStorePassword,
                                     String trustStoreType) throws IOException {
        //TODO: Not sure if the final code in artifactory should support the calls to the system properties or not.  Certainly allows for a faster short-term fix.
        KeyStore trustStore = null;

        if(trustStorePath == null) {
            trustStorePath = System.getProperty("javax.net.ssl.trustStore");
        }
        Log.debug("Truststore = " + trustStorePath);

        if( trustStorePassword == null) {
            trustStorePassword =
                    System.getProperty("javax.net.ssl.trustStorePassword");
        }
        Log.debug("TrustPass = " + trustStorePassword);

        if( trustStoreType == null) {
            trustStoreType = System.getProperty("javax.net.ssl.trustStoreType");
        }
        if(trustStoreType == null) {
            trustStoreType = DEFAULT_STORE_TYPE;
        }
        Log.debug("trustType = " + trustStoreType);

        if (trustStorePath != null){
            try {
                trustStore = getStore(trustStoreType, trustStorePath, trustStorePassword);
            } catch (IOException ioe) {
                Throwable cause = ioe.getCause();
                if (cause instanceof UnrecoverableKeyException) {
                    // Log a warning we had a password issue
                    Log.warn("Trust Store Provider had trouble reading the store because of a password issue:"+ "cause");
                    // Re-try
                    trustStore = getStore(trustStoreType, trustStorePath, null);
                } else {
                    throw ioe;
                }
            }
        }

        return trustStore;
    }

 /*
  * Gets the key- or truststore with the specified type, path, and password.
  */
    private KeyStore getStore(String type, String path,
                              String pass) throws IOException {

        KeyStore ks = null;
        InputStream istream = null;
        try {
            ks = KeyStore.getInstance(type);
        if(!("PKCS11".equalsIgnoreCase(type) ||
                    "".equalsIgnoreCase(path))) {
                File keyStoreFile = new File(path);
                istream = new FileInputStream(keyStoreFile);
            }

            char[] storePass = null;
            if (pass != null && !"".equals(pass)) {
                storePass = pass.toCharArray();
            }
            ks.load(istream, storePass);
        } catch (FileNotFoundException fnfe) {
            Log.error("Read store failed: "+fnfe.getMessage(), fnfe);
            throw fnfe;
        } catch (IOException ioe) {
            // May be expected when working with a trust store
            // Re-throw. Caller will catch and log as required
            throw ioe;
        } catch(Exception ex) {
            String msg = "Get Store failed: "+type+path+" ;; " + ex.getMessage();
            Log.error(msg, ex);
            throw new IOException(msg);
        }
        finally {
            if (istream != null) {
                try {
                    istream.close();
                } catch (IOException ioe) {
                    // Do nothing
                }
            }
        }
        return ks;
    }

    /**
     * May throw a runtime exception when the given URL is invalid.
     */
    public HttpClientConfigurator hostFromUrl(String urlStr) {
        if (!isBlank(urlStr)) {
            try {
                URL url = new URL(urlStr);
                host(url.getHost());
            } catch (MalformedURLException e) {
                throw new IllegalArgumentException("Cannot parse the url " + urlStr, e);
            }
        }
        return this;
    }

    /**
     * Ignores blank values
     */
    public HttpClientConfigurator host(String host) {
        if (!isBlank(host)) {
            this.host = host;
            builder.setRoutePlanner(new DefaultHostRoutePlanner(host));
        }
        return this;
    }

    public HttpClientConfigurator defaultMaxConnectionsPerHost(int maxConnectionsPerHost) {
        builder.setMaxConnPerRoute(maxConnectionsPerHost);
        return this;
    }

    public HttpClientConfigurator maxTotalConnections(int maxTotalConnections) {
        builder.setMaxConnTotal(maxTotalConnections);
        return this;
    }

    public HttpClientConfigurator connectionTimeout(int connectionTimeout) {
        config.setConnectTimeout(connectionTimeout);
        return this;
    }

    public HttpClientConfigurator soTimeout(int soTimeout) {
        config.setSocketTimeout(soTimeout);
        return this;
    }

    /**
     * see {@link org.apache.http.client.config.RequestConfig#isStaleConnectionCheckEnabled()}
     */
    public HttpClientConfigurator staleCheckingEnabled(boolean staleCheckingEnabled) {
        config.setStaleConnectionCheckEnabled(staleCheckingEnabled);
        return this;
    }

    /**
     * Disable request retries on service unavailability.
     */
    public HttpClientConfigurator noRetry() {
        return retry(0, false);
    }

    /**
     * Number of retry attempts. Default is 3 retries.
     *
     * @param retryCount Number of retry attempts. 0 means no retries.
     */
    public HttpClientConfigurator retry(int retryCount, boolean requestSentRetryEnabled) {
        if (retryCount == 0) {
            builder.disableAutomaticRetries();
        } else {
            builder.setRetryHandler(new DefaultHttpRequestRetryHandler(retryCount, requestSentRetryEnabled));
        }
        return this;
    }

    /**
     * Ignores blank or invalid input
     */
    public HttpClientConfigurator localAddress(String localAddress) {
        if (!isBlank(localAddress)) {
            try {
                InetAddress address = InetAddress.getByName(localAddress);
                config.setLocalAddress(address);
            } catch (UnknownHostException e) {
                throw new IllegalArgumentException("Invalid local address: " + localAddress, e);
            }
        }
        return this;
    }

    /**
     * Ignores null credentials
     */
    public HttpClientConfigurator authentication(UsernamePasswordCredentials creds) {
        if (creds != null) {
            authentication(creds.getUserName(), creds.getPassword());
        }

        return this;
    }

    /**
     * Ignores blank username input
     */
    public HttpClientConfigurator authentication(String username, String password) {
        if (!isBlank(username)) {
            if (isBlank(host)) {
                throw new IllegalStateException("Cannot configure authentication when host is not set.");
            }

            credsProvider.setCredentials(
                    new AuthScope(host, AuthScope.ANY_PORT, AuthScope.ANY_REALM),
                    new UsernamePasswordCredentials(username, password));

            builder.addInterceptorFirst(new PreemptiveAuthInterceptor());
        }
        return this;
    }

    private boolean isBlank(String string) {
        return string == null || string.isEmpty() || string.trim().isEmpty();
    }

    public HttpClientConfigurator proxy(ProxyDescriptor proxyDescriptor) {
        configureProxy(proxyDescriptor);
        return this;
    }

    private void configureProxy(ProxyDescriptor proxy) {
        if (proxy != null) {
            config.setProxy(new HttpHost(proxy.host, proxy.port));
            if (!isBlank(proxy.username)) {
                Credentials creds = null;
                if (!isBlank(proxy.domain)) {
                    creds = new UsernamePasswordCredentials(proxy.username, proxy.password);
                    //This will demote the NTLM authentication scheme so that the proxy won't barf
                    //when we try to give it traditional credentials. If the proxy doesn't do NTLM
                    //then this won't hurt it (jcej at tragus dot org)
                    List<String> authPrefs = Arrays.asList(AuthSchemes.DIGEST, AuthSchemes.BASIC, AuthSchemes.NTLM);
                    config.setProxyPreferredAuthSchemes(authPrefs);
                    // preemptive proxy authentication
                    builder.addInterceptorFirst(new ProxyPreemptiveAuthInterceptor());
                } else {
                    try {
                        String ntHost =
                                isBlank(proxy.ntHost) ? InetAddress.getLocalHost().getHostName() :
                                        proxy.ntHost;
                        creds = new NTCredentials(proxy.username, proxy.password, ntHost, proxy.domain);
                    } catch (UnknownHostException e) {
                        Log.error("Failed to determine required local hostname for NTLM credentials.", e);
                    }
                }
                if (creds != null) {
                    credsProvider.setCredentials(
                            new AuthScope(proxy.host, proxy.port, AuthScope.ANY_REALM), creds);
/*
                    if (proxy.getRedirectedToHostsList() != null) {
                        for (String hostName : proxy.getRedirectedToHostsList()) {
                            credsProvider.setCredentials(
                                    new AuthScope(hostName, AuthScope.ANY_PORT, AuthScope.ANY_REALM), creds);
                        }
                    }
*/
                }
            }
        }
    }

    private boolean hasCredentials() {
        return credsProvider.getCredentials(AuthScope.ANY) != null;
    }

    static class DefaultHostRoutePlanner extends DefaultRoutePlanner {

        private final HttpHost defaultHost;

        public DefaultHostRoutePlanner(String defaultHost) {
            super(DefaultSchemePortResolver.INSTANCE);
            this.defaultHost = new HttpHost(defaultHost);
        }

        @Override
        public HttpRoute determineRoute(HttpHost host, HttpRequest request, HttpContext context) throws HttpException {
            if (host == null) {
                host = defaultHost;
            }
            return super.determineRoute(host, request, context);
        }

        public HttpHost getDefaultHost() {
            return defaultHost;
        }
    }


}

class PreemptiveAuthInterceptor implements HttpRequestInterceptor {
    @Override
    public void process(HttpRequest request, HttpContext context) throws HttpException, IOException {
        HttpClientContext clientContext = HttpClientContext.adapt(context);
        AuthState authState = clientContext.getTargetAuthState();

        // If there's no auth scheme available yet, try to initialize it preemptively
        if (authState.getAuthScheme() == null) {
            CredentialsProvider credsProvider = clientContext.getCredentialsProvider();
            HttpHost targetHost = clientContext.getTargetHost();
            Credentials creds = credsProvider.getCredentials(
                    new AuthScope(targetHost.getHostName(), targetHost.getPort()));
            if (creds == null) {
                throw new HttpException("No credentials for preemptive authentication");
            }
            authState.update(new BasicScheme(), creds);
        }
    }
}

class ProxyPreemptiveAuthInterceptor implements HttpRequestInterceptor {
    @Override
    public void process(HttpRequest request, HttpContext context) throws HttpException, IOException {
        HttpClientContext clientContext = HttpClientContext.adapt(context);
        AuthState proxyAuthState = clientContext.getProxyAuthState();

        // If there's no auth scheme available yet, try to initialize it preemptively
        if (proxyAuthState.getAuthScheme() == null) {
            CredentialsProvider credsProvider = clientContext.getCredentialsProvider();
            RouteInfo route = clientContext.getHttpRoute();
            if (route == null) {
                Log.debug("No route found for " + clientContext.getTargetHost());
                return;
            }

            HttpHost proxyHost = route.getProxyHost();
            if (proxyHost == null) {
                Log.warn("No proxy host found in route " + route + " for host " + clientContext.getTargetHost());
                return;
            }

            Credentials creds = credsProvider.getCredentials(
                    new AuthScope(proxyHost.getHostName(), proxyHost.getPort()));
            if (creds == null) {
                Log.info("No credentials found for proxy: " + proxyHost);
                return;
            }
            proxyAuthState.update(new BasicScheme(ChallengeState.PROXY), creds);
        }
    }
}


class ProxyDescriptor {
    String host;
    int port;
    String username;
    String password;
    String ntHost;
    String domain;
}