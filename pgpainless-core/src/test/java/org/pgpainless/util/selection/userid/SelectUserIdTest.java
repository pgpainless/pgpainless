/*
 * Copyright 2021 Paul Schaub.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.pgpainless.util.selection.userid;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.key.protection.SecretKeyRingProtector;
import org.pgpainless.key.util.UserId;

import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

public class SelectUserIdTest {

    @Test
    public void test() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, PGPException {
        PGPSecretKeyRing secretKeys = PGPainless.generateKeyRing()
                .simpleEcKeyRing("<alice@wonderland.lit>");
        secretKeys = PGPainless.modifyKeyRing(secretKeys)
                .addUserId(
                        UserId.withName("Alice Liddell").noComment().withEmail("crazy@the-rabbit.hole"),
                        SecretKeyRingProtector.unprotectedKeys())
                .done();

        List<String> validEmail = SelectUserId.and(
                SelectUserId.validUserId(secretKeys),
                SelectUserId.containsEmailAddress("alice@wonderland.lit")
        ).selectUserIds(secretKeys);

        assertEquals(Collections.singletonList("<alice@wonderland.lit>"), validEmail);

        List<String> startsWithAlice = SelectUserId.startsWith("Alice").selectUserIds(secretKeys);
        assertEquals(Collections.singletonList("Alice Liddell <crazy@the-rabbit.hole>"), startsWithAlice);

        List<String> exactMatch = SelectUserId.or(
                SelectUserId.exactMatch("<alice@wonderland.lit>"),
                SelectUserId.startsWith("Not Found")
        ).selectUserIds(secretKeys);
        assertEquals(Collections.singletonList("<alice@wonderland.lit>"), exactMatch);
    }

    @Test
    public void testContainsSubstring() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, PGPException {
        PGPSecretKeyRing secretKeys = PGPainless.generateKeyRing().simpleEcKeyRing("wine drinker");
        secretKeys = PGPainless.modifyKeyRing(secretKeys)
                .addUserId("this is not a quine", SecretKeyRingProtector.unprotectedKeys())
                .addUserId("this is not a crime", SecretKeyRingProtector.unprotectedKeys())
                .done();

        List<String> containSubstring = SelectUserId.containsSubstring("ine")
                .selectUserIds(secretKeys);
        assertEquals(Arrays.asList("wine drinker", "this is not a quine"), containSubstring);
    }

    @Test
    public void testContainsEmailAddress() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, PGPException {
        PGPSecretKeyRing secretKeys = PGPainless.generateKeyRing().simpleEcKeyRing("Alice <alice@wonderland.lit>");

        assertEquals("Alice <alice@wonderland.lit>", SelectUserId.containsEmailAddress("alice@wonderland.lit").firstMatch(secretKeys));
        assertEquals("Alice <alice@wonderland.lit>", SelectUserId.containsEmailAddress("<alice@wonderland.lit>").firstMatch(secretKeys));

        assertNull(SelectUserId.containsEmailAddress("mad@hatter.lit").firstMatch(secretKeys));
    }

    @Test
    public void testAndOrNot() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, PGPException {
        PGPSecretKeyRing secretKeys = PGPainless.generateKeyRing().simpleEcKeyRing("Alice <alice@wonderland.lit>");
        secretKeys = PGPainless.modifyKeyRing(secretKeys)
                .addUserId("Alice <another@email.address>", SecretKeyRingProtector.unprotectedKeys())
                .addUserId("<crazy@the-rabbit.hole>", SecretKeyRingProtector.unprotectedKeys())
                .addUserId("Crazy Girl <alice@wonderland.lit>", SecretKeyRingProtector.unprotectedKeys())
                .done();

        List<String> or = SelectUserId.or(
                SelectUserId.containsEmailAddress("alice@wonderland.lit"),
                SelectUserId.startsWith("Alice"))
                .selectUserIds(secretKeys);
        assertEquals(Arrays.asList("Alice <alice@wonderland.lit>", "Alice <another@email.address>", "Crazy Girl <alice@wonderland.lit>"), or);

        List<String> and = SelectUserId.and(
                SelectUserId.containsEmailAddress("alice@wonderland.lit"),
                SelectUserId.startsWith("Alice"))
                .selectUserIds(secretKeys);
        assertEquals(Collections.singletonList("Alice <alice@wonderland.lit>"), and);

        List<String> not = SelectUserId.not(
                SelectUserId.startsWith("Alice"))
                .selectUserIds(secretKeys);
        assertEquals(Arrays.asList("<crazy@the-rabbit.hole>", "Crazy Girl <alice@wonderland.lit>"), not);
    }

    @Test
    public void testFirstMatch() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, PGPException {
        PGPSecretKeyRing secretKeys = PGPainless.generateKeyRing().simpleEcKeyRing("First UserID");
        secretKeys = PGPainless.modifyKeyRing(secretKeys)
                .addUserId("Second UserID", SecretKeyRingProtector.unprotectedKeys())
                .done();
        assertEquals("First UserID", SelectUserId.validUserId(secretKeys).firstMatch(secretKeys));
        assertEquals("Second UserID", SelectUserId.containsSubstring("Second").firstMatch(
                PGPainless.inspectKeyRing(secretKeys).getUserIds()
        ));
    }
}
