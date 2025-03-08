// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.util.selection.userid;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.key.protection.SecretKeyRingProtector;
import org.pgpainless.key.util.UserId;

public class SelectUserIdTest {

    @Test
    public void testSelectUserIds() throws PGPException {
        PGPSecretKeyRing secretKeys = PGPainless.generateKeyRing()
                .simpleEcKeyRing("<alice@wonderland.lit>")
                .getPGPSecretKeyRing();
        secretKeys = PGPainless.modifyKeyRing(secretKeys)
                .addUserId(
                        UserId.newBuilder().withName("Alice Liddell").noComment()
                                .withEmail("crazy@the-rabbit.hole").build(),
                        SecretKeyRingProtector.unprotectedKeys())
                .done();

        List<String> userIds = PGPainless.inspectKeyRing(secretKeys).getValidUserIds();
        List<String> validEmail = userIds.stream().filter(SelectUserId.and(
                SelectUserId.validUserId(secretKeys),
                SelectUserId.containsEmailAddress("alice@wonderland.lit")
        )).collect(Collectors.toList());

        assertEquals(Collections.singletonList("<alice@wonderland.lit>"), validEmail);

        List<String> startsWithAlice = userIds.stream().filter(SelectUserId.startsWith("Alice")).collect(Collectors.toList());
        assertEquals(Collections.singletonList("Alice Liddell <crazy@the-rabbit.hole>"), startsWithAlice);

        List<String> exactMatch = userIds.stream().filter(SelectUserId.or(
                SelectUserId.exactMatch("<alice@wonderland.lit>"),
                SelectUserId.startsWith("Not Found")
        )).collect(Collectors.toList());
        assertEquals(Collections.singletonList("<alice@wonderland.lit>"), exactMatch);
    }

    @Test
    public void testContainsSubstring() throws PGPException {
        PGPSecretKeyRing secretKeys = PGPainless.generateKeyRing().simpleEcKeyRing("wine drinker")
                .getPGPSecretKeyRing();
        secretKeys = PGPainless.modifyKeyRing(secretKeys)
                .addUserId("this is not a quine", SecretKeyRingProtector.unprotectedKeys())
                .addUserId("this is not a crime", SecretKeyRingProtector.unprotectedKeys())
                .done();

        List<String> userIds = PGPainless.inspectKeyRing(secretKeys).getValidUserIds();

        List<String> containSubstring = userIds.stream().filter(SelectUserId.containsSubstring("ine")).collect(Collectors.toList());
        assertEquals(Arrays.asList("wine drinker", "this is not a quine"), containSubstring);
    }

    @Test
    public void testContainsEmailAddress() {
        PGPSecretKeyRing secretKeys = PGPainless.generateKeyRing().simpleEcKeyRing("Alice <alice@wonderland.lit>")
                .getPGPSecretKeyRing();
        List<String> userIds = PGPainless.inspectKeyRing(secretKeys).getValidUserIds();

        assertEquals("Alice <alice@wonderland.lit>", userIds.stream().filter(
                SelectUserId.containsEmailAddress("alice@wonderland.lit")).findFirst().get());
        assertEquals("Alice <alice@wonderland.lit>", userIds.stream().filter(
                SelectUserId.containsEmailAddress("<alice@wonderland.lit>")).findFirst().get());

        assertFalse(userIds.stream().anyMatch(SelectUserId.containsEmailAddress("mad@hatter.lit")));
    }

    @Test
    public void testAndOrNot() throws PGPException {
        PGPSecretKeyRing secretKeys = PGPainless.generateKeyRing().simpleEcKeyRing("Alice <alice@wonderland.lit>")
                .getPGPSecretKeyRing();
        secretKeys = PGPainless.modifyKeyRing(secretKeys)
                .addUserId("Alice <another@email.address>", SecretKeyRingProtector.unprotectedKeys())
                .addUserId("<crazy@the-rabbit.hole>", SecretKeyRingProtector.unprotectedKeys())
                .addUserId("Crazy Girl <alice@wonderland.lit>", SecretKeyRingProtector.unprotectedKeys())
                .done();

        List<String> userIds = PGPainless.inspectKeyRing(secretKeys).getValidUserIds();

        List<String> or = userIds.stream().filter(SelectUserId.or(
                SelectUserId.containsEmailAddress("alice@wonderland.lit"),
                SelectUserId.startsWith("Alice"))).collect(Collectors.toList());
        assertEquals(Arrays.asList("Alice <alice@wonderland.lit>", "Alice <another@email.address>", "Crazy Girl <alice@wonderland.lit>"), or);

        List<String> and = userIds.stream().filter(SelectUserId.and(
                SelectUserId.containsEmailAddress("alice@wonderland.lit"),
                SelectUserId.startsWith("Alice"))).collect(Collectors.toList());
        assertEquals(Collections.singletonList("Alice <alice@wonderland.lit>"), and);

        List<String> not = userIds.stream().filter(SelectUserId.not(
                SelectUserId.startsWith("Alice"))).collect(Collectors.toList());
        assertEquals(Arrays.asList("<crazy@the-rabbit.hole>", "Crazy Girl <alice@wonderland.lit>"), not);
    }

    @Test
    public void testFirstMatch() throws PGPException {
        PGPSecretKeyRing secretKeys = PGPainless.generateKeyRing().simpleEcKeyRing("First UserID")
                .getPGPSecretKeyRing();
        secretKeys = PGPainless.modifyKeyRing(secretKeys)
                .addUserId("Second UserID", SecretKeyRingProtector.unprotectedKeys())
                .done();
        List<String> userIds = PGPainless.inspectKeyRing(secretKeys).getValidUserIds();
        assertEquals("First UserID", userIds.stream().filter(SelectUserId.validUserId(secretKeys)).findFirst().get());
        assertEquals("Second UserID", userIds.stream().filter(SelectUserId.containsSubstring("Second")).findFirst().get());
    }

    @Test
    public void testByEmail() {
        SelectUserId containsEmailAddress = SelectUserId.containsEmailAddress("alice@pgpainless.org");
        assertTrue(containsEmailAddress.accept("<alice@pgpainless.org>"));
        assertTrue(containsEmailAddress.accept("Alice <alice@pgpainless.org>"));

        SelectUserId byEmail = SelectUserId.byEmail("alice@pgpainless.org");
        assertTrue(byEmail.accept("alice@pgpainless.org"));
        assertTrue(byEmail.accept("<alice@pgpainless.org>"));
        assertTrue(byEmail.accept("Alice <alice@pgpainless.org>"));
    }
}
