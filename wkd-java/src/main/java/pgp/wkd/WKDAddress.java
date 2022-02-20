// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.wkd;

import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.codec.binary.ZBase32;

/**
 * Transform an email address into a WKD address.
 *
 * @see <a href="https://datatracker.ietf.org/doc/draft-koch-openpgp-webkey-service/">OpenPGP Web Key Directory</a>
 */
public final class WKDAddress {

    // RegEx for Email Addresses.
    // https://www.baeldung.com/java-email-validation-regex#regular-expression-by-rfc-5322-for-email-validation
    // Modified by adding capture groups '()' for local and domain part
    private static final Pattern PATTERN_EMAIL = Pattern.compile("^([a-zA-Z0-9_!#$%&'*+/=?`{|}~^.-]+)@([a-zA-Z0-9.-]+)$");

    // Firstname Lastname <email@address> [Optional Comment]
    // we are only interested in "email@address"
    private static final Pattern PATTERN_USER_ID = Pattern.compile("^.*\\<([a-zA-Z0-9_!#$%&'*+/=?`{|}~^.-]+@[a-zA-Z0-9.-]+)\\>.*");

    private static final ZBase32 zBase32 = new ZBase32();
    private static final Charset utf8 = Charset.forName("UTF8");

    private static final String SCHEME = "https://";
    private static final String SUBDOMAIN = "openpgpkey";
    private static final String PATH = "/.well-known/openpgpkey/";
    private static final String HU = "/hu/";
    private static final String PATH_HU = "/.well-known/openpgpkey/hu/";

    private WKDAddress() {

    }

    public static String emailFromUserId(String userId) {
        Matcher matcher = PATTERN_USER_ID.matcher(userId);
        if (!matcher.matches()) {
            throw new IllegalArgumentException("User-ID does not follow excepted pattern \"Firstname Lastname <email.address> [Optional Comment]\"");
        }

        String email = matcher.group(1);
        return email;
    }

    public static URI directFromUserId(String userId) {
        String email = emailFromUserId(userId);
        return directFromEmail(email);
    }

    public static URI directFromEmail(String email) {
        MailAddress mailAddress = parseMailAddress(email);

        return URI.create(SCHEME + mailAddress.getDomainPart() + PATH_HU + mailAddress.getHashedLocalPart() + "?l=" + mailAddress.getPercentEncodedLocalPart());
    }

    /**
     * Extract the email address from a user-id.
     * The user-id is expected to correspond to a RFC2822 name-addr.
     * The email address is expected to be framed by angle brackets.
     *
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc2822#section-3.4">RFC2822 - Internet Message Format §3.4: Address Specification</a>
     * @param userId user-id name-addr
     * @return WKD URI
     *
     * @throws IllegalArgumentException in case the user-id does not match the expected format
     */
    public static URI advancedFromUserId(String userId) {
        String email = emailFromUserId(userId);
        return advancedFromEmail(email);
    }

    /**
     * Translate an email address (localpart@domainpart) to a WKD URI.
     *
     * @param email email address
     * @return WKD URI
     * @throws IllegalArgumentException in case of a malformed email address
     */
    public static URI advancedFromEmail(String email) {
        MailAddress mailAddress = parseMailAddress(email);

        return URI.create(
                SCHEME + SUBDOMAIN + "." + mailAddress.getDomainPart() + PATH + mailAddress.getDomainPart()
                        + HU + mailAddress.getHashedLocalPart() + "?l=" + mailAddress.getPercentEncodedLocalPart()
        );
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

        public String getLowerCaseLocalPart() {
            return getLocalPart().toLowerCase();
        }

        public String getPercentEncodedLocalPart() {
            try {
                return URLEncoder.encode(getLocalPart(), "UTF-8");
            } catch (UnsupportedEncodingException e) {
                // UTF8 is a MUST on JVM implementations
                throw new AssertionError(e);
            }
        }

        public String getHashedLocalPart() {
            MessageDigest sha1;
            try {
                sha1 = MessageDigest.getInstance("SHA1");
            } catch (NoSuchAlgorithmException e) {
                // SHA-1 is a MUST on JVM implementations
                throw new AssertionError(e);
            }
            sha1.update(getLowerCaseLocalPart().getBytes(utf8));
            byte[] digest = sha1.digest();

            String base32KeyHandle = zBase32.encodeAsString(digest);
            return base32KeyHandle;
        }

        public String getDomainPart() {
            return domainPart.toLowerCase();
        }
    }
}
