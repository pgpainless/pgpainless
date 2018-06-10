package de.vanitasvitae.crypto.pgpainless.util;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.Iterator;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;

public class BCUtil {

    public static PGPPublicKeyRingCollection keyRingsToKeyRingCollection(PGPPublicKeyRing... rings)
            throws IOException, PGPException {
        return new PGPPublicKeyRingCollection(Arrays.asList(rings));
    }

    public static PGPSecretKeyRingCollection keyRingsToKeyRingCollection(PGPSecretKeyRing... rings)
            throws IOException, PGPException {
        return new PGPSecretKeyRingCollection(Arrays.asList(rings));
    }

    public static PGPPublicKeyRing publicKeyRingFromSecretKeyRing(PGPSecretKeyRing ring) throws IOException {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        for (Iterator<PGPPublicKey> i = ring.getPublicKeys(); i.hasNext(); ) {
            PGPPublicKey k = i.next();
            k.encode(buffer);
        }
        buffer.close();
        ByteArrayInputStream in = new ByteArrayInputStream(buffer.toByteArray());
        return new PGPPublicKeyRing(in, new BcKeyFingerprintCalculator());
    }
}