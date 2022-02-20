// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.wkd;

import org.apache.commons.codec.binary.ZBase32;

import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class WKDAddress {

    private static final String SCHEME = "https://";
    private static final String ADV_SUBDOMAIN = "openpgpkey.";
    private static final String DIRECT_WELL_KNOWN = "/.well-known/openpgpkey/hu/";
    private static String ADV_WELL_KNOWN(String domain) {
        return "/.well-known/openpgpkey/" + domain + "/hu/";
    }

    // RegEx for Email Addresses.
    // https://www.baeldung.com/java-email-validation-regex#regular-expression-by-rfc-5322-for-email-validation
    // Modified by adding capture groups '()' for local and domain part
    private static final Pattern PATTERN_EMAIL = Pattern.compile("^([a-zA-Z0-9_!#$%&'*+/=?`{|}~^.-]+)@([a-zA-Z0-9.-]+)$");

    private static final Charset utf8 = Charset.forName("UTF8");
    private static final ZBase32 zBase32 = new ZBase32();

    private final String localPart;
    private final String domainPart;
    private final String zbase32LocalPart;
    private final String percentEncodedLocalPart;

    public WKDAddress(String localPart, String domainPart) {
        this.localPart = localPart;
        this.domainPart = domainPart.toLowerCase();

        this.zbase32LocalPart = zbase32(this.localPart);
        this.percentEncodedLocalPart = percentEncode(this.localPart);
    }

    public static WKDAddress fromEmail(String email) {
        MailAddress mailAddress = parseMailAddress(email);
        return new WKDAddress(mailAddress.getLocalPart(), mailAddress.getDomainPart());
    }

    public URI getDirectMethodURI() {
        return URI.create(SCHEME + domainPart + DIRECT_WELL_KNOWN + zbase32LocalPart + "?l=" + percentEncodedLocalPart);
    }

    public URI getAdvancedMethodURI() {
        return URI.create(SCHEME + ADV_SUBDOMAIN + domainPart + ADV_WELL_KNOWN(domainPart) + zbase32LocalPart + "?l=" + percentEncodedLocalPart);
    }

    private String zbase32(String localPart) {
        MessageDigest sha1;
        try {
            sha1 = MessageDigest.getInstance("SHA1");
        } catch (NoSuchAlgorithmException e) {
            // SHA-1 is a MUST on JVM implementations
            throw new AssertionError(e);
        }
        sha1.update(localPart.toLowerCase().getBytes(utf8));
        byte[] digest = sha1.digest();

        String base32KeyHandle = zBase32.encodeAsString(digest);
        return base32KeyHandle;
    }

    private String percentEncode(String localPart) {
        try {
            return URLEncoder.encode(localPart, "UTF-8");
        } catch (UnsupportedEncodingException e) {
            // UTF8 is a MUST on JVM implementations
            throw new AssertionError(e);
        }
    }


    private static MailAddress parseMailAddress(String email) {
        Matcher matcher = PATTERN_EMAIL.matcher(email);
        if (!matcher.matches()) {
            throw new IllegalArgumentException("Invalid email address.");
        }

        String localPart = matcher.group(1);
        String domainPart = matcher.group(2);
        return new MailAddress(localPart, domainPart);
    }

    private static class MailAddress {
        private final String localPart;
        private final String domainPart;

        MailAddress(String localPart, String domainPart) {
            this.localPart = localPart;
            this.domainPart = domainPart;
        }

        public String getLocalPart() {
            return localPart;
        }

        public String getDomainPart() {
            return domainPart;
        }
    }
}
