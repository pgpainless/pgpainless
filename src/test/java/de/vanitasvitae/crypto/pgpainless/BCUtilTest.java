package de.vanitasvitae.crypto.pgpainless;

import static junit.framework.TestCase.assertEquals;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Iterator;

import de.vanitasvitae.crypto.pgpainless.util.BCUtil;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.junit.Test;

public class BCUtilTest extends AbstractPGPainlessTest {

    @Test
    public void test()
            throws PGPException, NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException,
            IOException {
        PGPSecretKeyRing sec = PGPainless.generateKeyRing().simpleEcKeyRing("Hallo Welt");
        PGPPublicKeyRing pub = BCUtil.publicKeyRingFromSecretKeyRing(sec);

        int secSize = 0;
        Iterator<PGPPublicKey> secPubIt = sec.getPublicKeys();
        while (secPubIt.hasNext()) {
            secPubIt.next();
            secSize++;
        }

        int pubSize = 0;
        Iterator<PGPPublicKey> pubPubIt = pub.getPublicKeys();
        while (pubPubIt.hasNext()) {
            pubPubIt.next();
            pubSize++;
        }

        assertEquals(secSize, pubSize);
    }
}
