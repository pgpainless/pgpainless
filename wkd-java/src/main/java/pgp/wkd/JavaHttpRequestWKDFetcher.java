// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.wkd;

import java.io.IOException;
import java.io.InputStream;
import java.net.ConnectException;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class JavaHttpRequestWKDFetcher implements IWKDFetcher {

    private static final Logger LOGGER = LoggerFactory.getLogger(JavaHttpRequestWKDFetcher.class);

    @Override
    public InputStream fetch(WKDAddress address) throws IOException {
        URI advanced = address.getAdvancedMethodURI();
        IOException advancedException;
        try {
            return tryFetchUri(advanced);
        } catch (IOException e) {
            advancedException = e;
            LOGGER.debug("Could not fetch key using advanced method from " + advanced.toString(), e);
        }

        URI direct = address.getDirectMethodURI();
        try {
            return tryFetchUri(direct);
        } catch (IOException e) {
            advancedException.addSuppressed(e);
            LOGGER.debug("Could not fetch key using direct method from " + direct.toString(), e);
            throw advancedException;
        }
    }

    private InputStream tryFetchUri(URI uri) throws IOException {
        HttpURLConnection con = getConnection(uri);
        con.setRequestMethod("GET");

        con.setConnectTimeout(5000);
        con.setReadTimeout(5000);
        con.setInstanceFollowRedirects(false);

        int status = con.getResponseCode();
        if (status != 200) {
            throw new ConnectException("Connection was unsuccessful");
        }
        LOGGER.debug("Successfully fetched key from " + uri);
        return con.getInputStream();
    }

    private HttpURLConnection getConnection(URI uri) throws IOException {
        URL url = uri.toURL();
        return (HttpURLConnection) url.openConnection();
    }

    public static void main(String[] args) {
        if (args.length != 1) {
            throw new IllegalArgumentException("Expect a single argument email address");
        }

        String email = args[0];
        WKDAddress address = WKDAddress.fromEmail(email);

        JavaHttpRequestWKDFetcher fetch = new JavaHttpRequestWKDFetcher();
        try {
            InputStream inputStream = fetch.fetch(address);
            byte[] buf = new byte[4096];
            int read;
            while ((read = inputStream.read(buf)) != -1) {
                System.out.write(buf, 0, read);
            }
            inputStream.close();
            System.exit(0);
        } catch (IOException e) {
            LOGGER.debug("Could not fetch key.", e);
            System.exit(1);
        }
    }
}
