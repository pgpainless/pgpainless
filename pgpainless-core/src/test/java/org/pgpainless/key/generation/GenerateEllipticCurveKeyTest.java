package org.pgpainless.key.generation;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;

import org.bouncycastle.openpgp.PGPException;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.key.collection.PGPKeyRing;
import org.pgpainless.key.generation.type.EDDSA;
import org.pgpainless.key.generation.type.XDH;
import org.pgpainless.key.generation.type.curve.EdDSACurve;
import org.pgpainless.key.generation.type.curve.XDHCurve;
import org.pgpainless.key.util.UserId;
import org.pgpainless.util.ArmorUtils;

public class GenerateEllipticCurveKeyTest {

    @Test
    public void test() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, PGPException, IOException {
        PGPKeyRing keyRing = PGPainless.generateKeyRing()
                .withSubKey(KeySpec.getBuilder(XDH.fromCurve(XDHCurve._X25519))
                        .withDefaultKeyFlags()
                        .withDefaultAlgorithms())
                .withMasterKey(KeySpec.getBuilder(EDDSA.fromCurve(EdDSACurve._Ed25519))
                        .withDefaultKeyFlags()
                        .withDefaultAlgorithms())
                .withPrimaryUserId(UserId.onlyEmail("alice@wonderland.lit").toString())
                .withoutPassphrase()
                .build();

        System.out.println(ArmorUtils.toAsciiArmoredString(keyRing.getPublicKeys()));
    }
}
