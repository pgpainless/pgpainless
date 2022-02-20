// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.wkd;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.net.URI;

import org.junit.jupiter.api.Test;

public class WKDResolverTest {

    @Test
    public void testUserIdToUri() {
        String userId = "Joe Doe <joe.doe@example.org> [Work Address]";
        URI expectedURI = URI.create("https://example.org/.well-known/openpgpkey/hu/iy9q119eutrkn8s1mk4r39qejnbu3n5q");

        URI actual = new UserIdToWKDAddress().userIdToUri(userId);
        assertEquals(expectedURI, actual);
    }

    @Test
    public void testMailToUri() {
        String mailAddress = "Joe.Doe@Example.ORG";
        URI expectedURI = URI.create("https://example.org/.well-known/openpgpkey/hu/iy9q119eutrkn8s1mk4r39qejnbu3n5q");

        URI actual = new UserIdToWKDAddress().mailToUri(mailAddress);
        assertEquals(expectedURI, actual);
    }

    @Test
    public void testInvalidEmailToUri() {
        UserIdToWKDAddress uid2wkd = new UserIdToWKDAddress();
        assertThrows(IllegalArgumentException.class, () -> uid2wkd.mailToUri("john.doe"));
        assertThrows(IllegalArgumentException.class, () -> uid2wkd.mailToUri("@example.org"));
        assertThrows(IllegalArgumentException.class, () -> uid2wkd.mailToUri("john doe@example.org"));
        assertThrows(IllegalArgumentException.class, () -> uid2wkd.mailToUri("john.doe@example org"));
    }
}
