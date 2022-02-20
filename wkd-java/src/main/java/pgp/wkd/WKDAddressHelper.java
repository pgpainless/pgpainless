// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.wkd;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class WKDAddressHelper {

    // Firstname Lastname <email@address> [Optional Comment]
    // we are only interested in "email@address"
    private static final Pattern PATTERN_USER_ID = Pattern.compile("^.*\\<([a-zA-Z0-9_!#$%&'*+/=?`{|}~^.-]+@[a-zA-Z0-9.-]+)\\>.*");

    public static String emailFromUserId(String userId) {
        Matcher matcher = PATTERN_USER_ID.matcher(userId);
        if (!matcher.matches()) {
            throw new IllegalArgumentException("User-ID does not follow excepted pattern \"Firstname Lastname <email.address> [Optional Comment]\"");
        }

        String email = matcher.group(1);
        return email;
    }

    public static WKDAddress wkdAddressFromUserId(String userId) {
        String email = emailFromUserId(userId);
        return WKDAddress.fromEmail(email);
    }
}
