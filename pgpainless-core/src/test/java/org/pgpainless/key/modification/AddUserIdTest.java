// SPDX-FileCopyrightText: 2020 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.modification;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.util.Iterator;
import java.util.NoSuchElementException;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.pgpainless.PGPainless;
import org.pgpainless.implementation.ImplementationFactory;
import org.pgpainless.key.TestKeys;
import org.pgpainless.key.protection.PasswordBasedSecretKeyRingProtector;
import org.pgpainless.key.protection.SecretKeyRingProtector;
import org.pgpainless.key.protection.UnprotectedKeysProtector;
import org.pgpainless.util.Passphrase;

public class AddUserIdTest {

    @ParameterizedTest
    @MethodSource("org.pgpainless.util.TestImplementationFactoryProvider#provideImplementationFactories")
    public void addUserIdToExistingKeyRing(ImplementationFactory implementationFactory) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, PGPException {
        ImplementationFactory.setFactoryImplementation(implementationFactory);
        PGPSecretKeyRing secretKeys = PGPainless.generateKeyRing().simpleEcKeyRing("alice@wonderland.lit", "rabb1th0le");

        Iterator<String> userIds = secretKeys.getSecretKey().getPublicKey().getUserIDs();
        assertEquals("alice@wonderland.lit", userIds.next());
        assertFalse(userIds.hasNext());

        SecretKeyRingProtector protector = PasswordBasedSecretKeyRingProtector.forKey(secretKeys, Passphrase.fromPassword("rabb1th0le"));
        secretKeys = PGPainless.modifyKeyRing(secretKeys)
                .addUserId("cheshirecat@wonderland.lit", protector)
                .done();

        userIds = secretKeys.getPublicKey().getUserIDs();
        assertEquals("alice@wonderland.lit", userIds.next());
        assertEquals("cheshirecat@wonderland.lit", userIds.next());
        assertFalse(userIds.hasNext());

        secretKeys = PGPainless.modifyKeyRing(secretKeys)
                .deleteUserId("cheshirecat@wonderland.lit", protector)
                .done();

        userIds = secretKeys.getPublicKey().getUserIDs();
        assertEquals("alice@wonderland.lit", userIds.next());
        assertFalse(userIds.hasNext());
    }

    @ParameterizedTest
    @MethodSource("org.pgpainless.util.TestImplementationFactoryProvider#provideImplementationFactories")
    public void deleteUserId_noSuchElementExceptionForMissingUserId(ImplementationFactory implementationFactory) throws IOException, PGPException {
        ImplementationFactory.setFactoryImplementation(implementationFactory);

        PGPSecretKeyRing secretKeys = TestKeys.getCryptieSecretKeyRing();
        assertThrows(NoSuchElementException.class, () -> PGPainless.modifyKeyRing(secretKeys)
                .deleteUserId("invalid@user.id", new UnprotectedKeysProtector()));
    }

    @ParameterizedTest
    @MethodSource("org.pgpainless.util.TestImplementationFactoryProvider#provideImplementationFactories")
    public void deleteExistingAndAddNewUserIdToExistingKeyRing(ImplementationFactory implementationFactory) throws PGPException, IOException {
        ImplementationFactory.setFactoryImplementation(implementationFactory);

        final String ARMORED_PRIVATE_KEY =
                "-----BEGIN PGP PRIVATE KEY BLOCK-----\r\n\r\n" +
                        "xVgEX6UIExYJKwYBBAHaRw8BAQdAMfHf64wPQ2LC9In5AKYU/KT1qWvI7e7a\r\n" +
                        "Xr+LWeQGUKIAAQCcB3zZlHfepQT26LIwbTDn4lvQ9LuD1fk2hK6i9FXFxxO7\r\n" +
                        "zRI8dXNlckBleGFtcGxlLmNvbT7CjwQQFgoAIAUCX6UIEwYLCQcIAwIEFQgK\r\n" +
                        "AgQWAgEAAhkBAhsDAh4BACEJEEoCtcZ3snFuFiEENY1GQZqrKQqgUAXASgK1\r\n" +
                        "xneycW6P6AEA5iXFK+fWpj0vn3xpKEuFRqvytPKFzhwd4wEvL+IGSPEBALE/\r\n" +
                        "pZdMzsDoKPENiLFpboDVNVJScwFXIleKmtNaRycFx10EX6UIExIKKwYBBAGX\r\n" +
                        "VQEFAQEHQBDdeawWVNqYkP8c/ihLEUlVpn8cQw7rmRc/sIhdAXhfAwEIBwAA\r\n" +
                        "/0Jy7IelcHDjxE3OzagEzSxNrCVw8uPHNRl8s6iP+CQYEfHCeAQYFggACQUC\r\n" +
                        "X6UIEwIbDAAhCRBKArXGd7JxbhYhBDWNRkGaqykKoFAFwEoCtcZ3snFuWp8B\r\n" +
                        "AIzRBYJSfZzlvlyyPhrbXJoYSICGNy/5x7noXjp/ByeOAQDnTbQi4XwXJrU4\r\n" +
                        "A8Nl9eyz16ZWUzEPwfWgahIG1eQDDA==\r\n" +
                        "=bk4o\r\n" +
                        "-----END PGP PRIVATE KEY BLOCK-----\r\n";

        PGPSecretKeyRing secretKeys = PGPainless.readKeyRing().secretKeyRing(ARMORED_PRIVATE_KEY);
        Iterator<String> userIds = secretKeys.getSecretKey().getPublicKey().getUserIDs();
        assertEquals("<user@example.com>", userIds.next());
        assertFalse(userIds.hasNext());

        SecretKeyRingProtector protector = new UnprotectedKeysProtector();
        secretKeys = PGPainless.modifyKeyRing(secretKeys)
                .deleteUserId("<user@example.com>", protector)
                .addUserId("cheshirecat@wonderland.lit", protector)
                .done();

        userIds = secretKeys.getSecretKey().getPublicKey().getUserIDs();
        assertEquals("cheshirecat@wonderland.lit", userIds.next());
        assertFalse(userIds.hasNext());
    }
}
