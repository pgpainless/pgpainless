// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.signature.builder;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;

import org.bouncycastle.bcpg.KeyIdentifier;
import org.bouncycastle.bcpg.sig.PrimaryUserID;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.api.OpenPGPKey;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.HashAlgorithm;
import org.pgpainless.algorithm.KeyFlag;
import org.pgpainless.algorithm.SignatureType;
import org.pgpainless.key.protection.SecretKeyRingProtector;
import org.pgpainless.signature.subpackets.SignatureSubpackets;

public class UniversalSignatureBuilderTest {

    private static final String KEY = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
            "Version: PGPainless\n" +
            "Comment: 9611 510F 313E DBC2 BBBC  DC24 3BAD F1F8 3E70 DC34\n" +
            "Comment: Signora Universa <signora@pgpainless.org>\n" +
            "\n" +
            "lFgEY4DKKRYJKwYBBAHaRw8BAQdA65vJxvvLASI/gczDP8ZKH4C+16MLU7F5iP91\n" +
            "8WWUqM0AAQCRSTHLLQWT9tuNRgkG3xaIiBGkEGD7Ou/R3oga6tc1MA8UtClTaWdu\n" +
            "b3JhIFVuaXZlcnNhIDxzaWdub3JhQHBncGFpbmxlc3Mub3JnPoiPBBMWCgBBBQJj\n" +
            "gMopCRA7rfH4PnDcNBYhBJYRUQ8xPtvCu7zcJDut8fg+cNw0Ap4BApsBBRYCAwEA\n" +
            "BAsJCAcFFQoJCAsCmQEAAOgMAPwIOXWt3EBBusK5Ps3m7p/5HsecZv3IXtscEQBx\n" +
            "vKlULwD/YuLP1XJSqcE2cQJRNt6OLi9Nt02MKBYkhWrRCYZAcQicXQRjgMopEgor\n" +
            "BgEEAZdVAQUBAQdAWTstuhvHwmSXaQ4Vh8yxl0DZcvjrWkZI+n9/uFBxEmoDAQgH\n" +
            "AAD/eRt6kgOMzWsTuM00am4UhSygxmDt7h6JkBTnpyyhK0gPiYh1BBgWCgAdBQJj\n" +
            "gMopAp4BApsMBRYCAwEABAsJCAcFFQoJCAsACgkQO63x+D5w3DRnZAEA6GlS9Tw8\n" +
            "9SJlUvh5aciYSlQUplnEdng+Pvzbj74zcXIA/2OkyMN428ddNhkHWWkZCMOxApum\n" +
            "/zNDSYMwvByQ2KcFnFgEY4DKKRYJKwYBBAHaRw8BAQdAfhPrtVuG3g/zXF51VrPv\n" +
            "kpQQk9aqjrkBMI0qlztBpu0AAP9Mw7NCsAVwg9CgmSzG2ATIDp3yf/4BGVYDs7qu\n" +
            "+sbn7xKIiNUEGBYKAH0FAmOAyikCngECmwIFFgIDAQAECwkIBwUVCgkIC18gBBkW\n" +
            "CgAGBQJjgMopAAoJENmzwZA/hq5ZCqIBAMYeOnASBd+WWta7Teh3g7Bl7sFY42Qy\n" +
            "0OnaSGk/pLm9AP4yC62Xpb9DhWeiQIOY7k5n4lhNn173IfzDK6KXzBKkBgAKCRA7\n" +
            "rfH4PnDcNMInAP4oanG9tbuczBNLN3JY4Hg4AaB+w5kfdOJxKwnAw7U0cgEAtasg\n" +
            "67qSjHvsEvjNKeXzUm+db7NWP3fpIHxAmjWVjwM=\n" +
            "=Dqbd\n" +
            "-----END PGP PRIVATE KEY BLOCK-----";

    private OpenPGPKey secretKeys;
    private final SecretKeyRingProtector protector = SecretKeyRingProtector.unprotectedKeys();

    @BeforeEach
    public void parseKey() throws IOException {
        secretKeys = PGPainless.getInstance().readKey().parseKey(KEY);
    }

    @Test
    public void createPetNameSignature() throws PGPException {
        OpenPGPKey.OpenPGPSecretKey signingKey = secretKeys.getPrimarySecretKey();
        PGPSignature archetype = signingKey.getPublicKey().getPGPPublicKey().getSignatures().next();
        UniversalSignatureBuilder builder = new UniversalSignatureBuilder(
                signingKey, protector, archetype);

        builder.applyCallback(new SignatureSubpackets.Callback() {
            @Override
            public void modifyHashedSubpackets(SignatureSubpackets hashedSubpackets) {
                hashedSubpackets.setExportable(true, false);
                hashedSubpackets.setPrimaryUserId(new PrimaryUserID(false, false));
            }
        });

        PGPSignatureGenerator generator = builder.getSignatureGenerator();

        String petName = "mykey";
        PGPSignature petNameSig = generator.generateCertification(petName, secretKeys.getPrimarySecretKey().getPublicKey().getPGPPublicKey());

        assertEquals(SignatureType.POSITIVE_CERTIFICATION.getCode(), petNameSig.getSignatureType());
        assertEquals(4, petNameSig.getVersion());
        assertTrue(KeyIdentifier.matches(petNameSig.getKeyIdentifiers(), signingKey.getKeyIdentifier(), true));
        assertEquals(HashAlgorithm.SHA512.getAlgorithmId(), petNameSig.getHashAlgorithm());
        assertEquals(KeyFlag.toBitmask(KeyFlag.CERTIFY_OTHER), petNameSig.getHashedSubPackets().getKeyFlags());
        assertFalse(petNameSig.getHashedSubPackets().isExportable());
        assertFalse(petNameSig.getHashedSubPackets().isPrimaryUserID());
    }
}
