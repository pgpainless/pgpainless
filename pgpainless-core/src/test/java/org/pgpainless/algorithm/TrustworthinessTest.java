// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.algorithm;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

public class TrustworthinessTest {

    @Test
    public void fullyTrustedIntroducer() {
        Trustworthiness it = Trustworthiness.fullyTrusted().introducer();
        assertTrue(it.isFullyTrusted());
        assertFalse(it.isNotTrusted());

        assertTrue(it.isIntroducer());
        assertFalse(it.canIntroduce(it));
    }

    @Test
    public void marginallyTrustedIntroducer() {
        Trustworthiness it = Trustworthiness.marginallyTrusted().introducer();
        assertFalse(it.isFullyTrusted());
        assertTrue(it.isMarginallyTrusted());
        assertFalse(it.isNotTrusted());

        assertTrue(it.isIntroducer());
        assertFalse(it.canIntroduce(2));
    }

    @Test
    public void nonTrustedIntroducer() {
        Trustworthiness it = Trustworthiness.untrusted().introducer();
        assertTrue(it.isNotTrusted());
        assertFalse(it.isMarginallyTrusted());
        assertFalse(it.isFullyTrusted());

        assertTrue(it.isIntroducer());
    }

    @Test
    public void trustedMetaIntroducer() {
        Trustworthiness it = Trustworthiness.fullyTrusted().metaIntroducer();
        assertTrue(it.isFullyTrusted());
        assertTrue(it.isIntroducer());

        Trustworthiness that = Trustworthiness.fullyTrusted().introducer();
        assertTrue(it.canIntroduce(that));
        assertFalse(that.canIntroduce(it));
    }

    @Test
    public void invalidArguments() {
        assertThrows(IllegalArgumentException.class, () -> new Trustworthiness(300, 1));
        assertThrows(IllegalArgumentException.class, () -> new Trustworthiness(60, 300));
        assertThrows(IllegalArgumentException.class, () -> new Trustworthiness(-4, 1));
        assertThrows(IllegalArgumentException.class, () -> new Trustworthiness(120, -1));
    }

    @Test
    public void inBetweenValues() {
        Trustworthiness it = new Trustworthiness(30, 1);
        assertTrue(it.isMarginallyTrusted());
        assertFalse(it.isFullyTrusted());

        it = new Trustworthiness(140, 1);
        assertTrue(it.isFullyTrusted());
    }
}
