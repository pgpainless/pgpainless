// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.wkd;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.codec.binary.ZBase32;

public class UserIdToWKDAddress {

    // RegEx for Email Addresses
    // https://www.baeldung.com/java-email-validation-regex#regular-expression-by-rfc-5322-for-email-validation
    // Modified by adding capture groups '()' for local and domain part
    private static final Pattern PATTERN_EMAIL = Pattern.compile("^([a-zA-Z0-9_!#$%&'*+/=?`{|}~^.-]+)@([a-zA-Z0-9.-]+)$");
    private static final Pattern PATTERN_USER_ID = Pattern.compile("^.*\\<([a-zA-Z0-9_!#$%&'*+/=?`{|}~^.-]+@[a-zA-Z0-9.-]+)\\>.*");

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
    public URI userIdToUri(String userId) {
        String lowerCase = userId.toLowerCase();
        Matcher matcher = PATTERN_USER_ID.matcher(lowerCase);
        if (!matcher.matches()) {
            throw new IllegalArgumentException("User-ID does not follow excepted pattern \"Firstname Lastname <email.address> [Optional Comment]\"");
        }
        String email = matcher.group(1);
        return mailToUri(email);
    }

    /**
     * Translate an email address (localpart@domainpart) to a WKD URI.
     *
     * @param email email address
     * @return WKD URI
     * @throws IllegalArgumentException in case of a malformed email address
     */
    public URI mailToUri(String email) {
        String lowerCase = email.toLowerCase();
        Matcher matcher = PATTERN_EMAIL.matcher(lowerCase);
        if (!matcher.matches()) {
            throw new IllegalArgumentException("Invalid email address.");
        }

        String localPart = matcher.group(1);
        String domainPart = matcher.group(2);

        MessageDigest sha1;
        try {
            sha1 = MessageDigest.getInstance("SHA1");
        } catch (NoSuchAlgorithmException e) {
            throw new AssertionError("SHA-1 is available on all JVMs.", e);
        }
        sha1.update(localPart.getBytes(StandardCharsets.UTF_8));
        byte[] digest = sha1.digest();

        String base32KeyHandle = new ZBase32().encodeAsString(digest);

        return URI.create("https://" + domainPart + "/.well-known/openpgpkey/hu/" + base32KeyHandle);
    }
}
