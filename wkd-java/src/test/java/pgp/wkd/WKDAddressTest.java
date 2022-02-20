// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.wkd;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.net.URI;
import java.util.Arrays;

import org.junit.jupiter.api.Test;

public class WKDAddressTest {

    @Test
    public void testAdvancedFromUserId() {
        String userId = "Joe Doe <Joe.Doe@Example.ORG> [Work Address]";
        URI expectedURI = URI.create("https://openpgpkey.example.org/.well-known/openpgpkey/example.org/hu/iy9q119eutrkn8s1mk4r39qejnbu3n5q?l=Joe.Doe");

        URI actual = WKDAddress.advancedFromUserId(userId);
        assertEquals(expectedURI, actual);
    }

    @Test
    public void testDirectFromUserId2() {
        String userId = "<alice@pgpainless.org>";
        URI expected = URI.create("https://pgpainless.org/.well-known/openpgpkey/hu/kei1q4tipxxu1yj79k9kfukdhfy631xe?l=alice");
        URI actual = WKDAddress.directFromUserId(userId);
        assertEquals(expected, actual);
    }

    @Test
    public void testDirectFromEmail() {
        String mailAddress = "Joe.Doe@Example.ORG";
        URI expected = URI.create("https://example.org/.well-known/openpgpkey/hu/iy9q119eutrkn8s1mk4r39qejnbu3n5q?l=Joe.Doe");

        URI actual = WKDAddress.directFromEmail(mailAddress);
        assertEquals(expected, actual);
    }

    @Test
    public void testAdvancedFromEmail() {
        String mailAddress = "Joe.Doe@Example.ORG";
        URI expected = URI.create("https://openpgpkey.example.org/.well-known/openpgpkey/example.org/hu/iy9q119eutrkn8s1mk4r39qejnbu3n5q?l=Joe.Doe");

        URI actual = WKDAddress.advancedFromEmail(mailAddress);
        assertEquals(expected, actual);
    }

    @Test
    public void testFromInvalidUserid() {
        for (String brokenUserId : Arrays.asList(
                "Alice <alice>",
                "Alice <alice@example.org",
                "Alice",
                "John Doe <john doe@example.org>",
                "John Doe <john.doe@example org>",
                "John Doe <john<example.org>",
                "John Doe [The Real One]",
                "<John Doe",
                "Don Joeh>")) {
            assertThrows(IllegalArgumentException.class, () -> WKDAddress.directFromUserId(brokenUserId));
            assertThrows(IllegalArgumentException.class, () -> WKDAddress.advancedFromUserId(brokenUserId));
        }
    }

    @Test
    public void testFromInvalidEmail() {
        for (String brokenEmail : Arrays.asList("john.doe", "@example.org", "john doe@example.org", "john.doe@example org")) {
            assertThrows(IllegalArgumentException.class, () -> WKDAddress.directFromEmail(brokenEmail));
            assertThrows(IllegalArgumentException.class, () -> WKDAddress.advancedFromEmail(brokenEmail));
        }
    }
}
