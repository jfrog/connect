package com.yossis.net;

import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;

import java.io.IOException;
import java.net.URL;
import java.net.URLConnection;
import java.util.EnumMap;

/**
 * @author Yossi Shaul
 */
public class connect {
    enum Options { PROXY_HOST, PROXY_PORT, PROXY_USERNAME,
        PROXY_PASSWORD, REMOTE_USERNAME,
        REMOTE_PASSWORD, USE_HTTP_CLIENT(true),
        CONNECT_TIMEOUT;

        boolean hasValue;
        String flagName;

        Options() {
            this.flagName = "--" + name().toLowerCase().replace('_','-');
            this.hasValue = true;
        }

        Options(boolean pureFlag) {
            this.flagName = "--" + name().toLowerCase().replace('_','-');
            this.hasValue = !pureFlag;
        }
    }

    static EnumMap<Options, String> options = new EnumMap<Options, String>(Options.class);

    public static void main(String[] args) throws IOException {
        if (args.length < 1) {
            usageError();
        }
        String destUrl = args[0];
        int i = 1;
        while (i < args.length) {
            String arg = args[++i];
            boolean found = false;
            for (Options opts : Options.values()) {
                if (opts.flagName.equals(arg)) {
                    if (opts.hasValue) {
                        if (i >= args.length) {
                            usageError();
                        }
                        String val = args[++i];
                        options.put(opts, val);
                    } else {
                        options.put(opts, "on");
                    }
                    found = true;
                    break;
                }
            }
            if (!found) usageError();
        }
        
        // for any options beside connect timeout we need HTTP client
        boolean useHttpClient = true;
        if (options.isEmpty() || (options.size() == 1 && options.containsKey(Options.CONNECT_TIMEOUT))) {
            useHttpClient = false;
        }

        if (useHttpClient) {
            HttpClientConfigurator configurator = new HttpClientConfigurator();
            configurator.hostFromUrl(destUrl);
            ProxyDescriptor proxyDescriptor = null;
            boolean credsSet = false;
            for (Options opts : options.keySet()) {
                switch (opts) {
                    case CONNECT_TIMEOUT:
                        configurator.soTimeout(Integer.valueOf(options.get(Options.CONNECT_TIMEOUT)));
                        break;
                    case REMOTE_USERNAME:
                    case REMOTE_PASSWORD:
                        if (!credsSet) {
                            configurator.authentication(options.get(Options.REMOTE_USERNAME), options.get(Options.REMOTE_PASSWORD));
                            credsSet = true;
                        }
                        break;
                    case PROXY_HOST:
                    case PROXY_PORT:
                    case PROXY_USERNAME:
                    case PROXY_PASSWORD:
                        if (proxyDescriptor == null) {
                            proxyDescriptor = new ProxyDescriptor();
                        }
                        proxyDescriptor.host = options.get(Options.PROXY_HOST);
                        if (options.containsKey(Options.PROXY_PORT)) {
                            proxyDescriptor.port = Integer.valueOf(options.get(Options.PROXY_PORT));
                        }
                        proxyDescriptor.username = options.get(Options.PROXY_USERNAME);
                        proxyDescriptor.password = options.get(Options.PROXY_PASSWORD);
                        break;
                }
            }
            if (proxyDescriptor != null) {
                configurator.proxy(proxyDescriptor);
            }
            CloseableHttpResponse execute = configurator.getClient().execute(new HttpGet(destUrl));
            System.out.println("Successfully connected using HTTP client to: " + destUrl);
            execute.close();
        } else {
            URLConnection urlConnection = new URL(destUrl).openConnection();
            int timeout = 10000;
            if (options.containsKey(Options.CONNECT_TIMEOUT)) {
                timeout = Integer.valueOf(options.get(Options.CONNECT_TIMEOUT));
            }
            urlConnection.setConnectTimeout(timeout);
            urlConnection.connect();
            System.out.println("Successfully connected using simple Java URL to: " + destUrl);
        }
    }

    private static void usageError() {
        System.err.println("Usage: connect DESTINATION_URL [--proxy-host host] [--proxy-port port:8080] [--use-http-client]");
        System.exit(1);
    }

}
