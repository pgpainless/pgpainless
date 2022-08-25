// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.encryption_signing;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.util.io.Streams;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.certificate_store.MergeCallbacks;
import org.pgpainless.certificate_store.PGPainlessCertD;
import org.pgpainless.key.OpenPgpFingerprint;
import pgp.cert_d.PGPCertificateStoreAdapter;
import pgp.certificate_store.certificate.Certificate;
import pgp.certificate_store.exception.BadDataException;
import pgp.certificate_store.exception.BadNameException;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

import static org.junit.jupiter.api.Assertions.assertTrue;

public class EncryptWithKeyFromKeyStoreTest {

    // Collection of 3 certificates (fingerprints below)
    private static final String CERT_COLLECTION = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
            "Version: BCPG v1.71\n" +
            "\n" +
            "mDMEYwemqhYJKwYBBAHaRw8BAQdAkhI29iXd05I2msAucVCmM2Chg52093a3MdHs\n" +
            "NHu83i+0FEEgPGFAcGdwYWlubGVzcy5vcmc+iI8EExYKAEEFAmMHpqoJEAcHMNbM\n" +
            "aq4mFiEEdjJKQcwZwKozs8H2Bwcw1sxqriYCngECmwEFFgIDAQAECwkIBwUVCgkI\n" +
            "CwKZAQAAoZcBAPhMQ8TLPRMLiWcNi4bO3A9OonFpxOyfLRC8yiJSL6bbAQDcMylf\n" +
            "pgOZGQ+uxWPokoJtWQt7I9IWsBxrwyW8iUniDbg4BGMHpqoSCisGAQQBl1UBBQEB\n" +
            "B0D9g9P9VCLNFKteqgESsYK+OKeeDDk3LRgcsxANBkWNcwMBCAeIdQQYFgoAHQUC\n" +
            "YwemqgKeAQKbDAUWAgMBAAQLCQgHBRUKCQgLAAoJEAcHMNbMaq4ml8MBAL8EUAIS\n" +
            "cusSuhIJpep961GS7dvUjn/Hg0TW5llUzg8fAQCl3vSqbSsNAUxmrOr3600IuyM2\n" +
            "EFlE412iEa5lhc/oArgzBGMHpqoWCSsGAQQB2kcPAQEHQKgUT/3nK/hqpgYR9zpw\n" +
            "2AYOXsJSHRdJOGW6dEMRvIBaiNUEGBYKAH0FAmMHpqoCngECmwIFFgIDAQAECwkI\n" +
            "BwUVCgkIC18gBBkWCgAGBQJjB6aqAAoJEGkhuqcOCjqNAfMA/3eG/POfM+6INiC3\n" +
            "DY7mTMgSEqjojd3aBWAGdbGuQ0b+AQDgfhLFYN/Ip6dvbEAhf8d0TCrs4dFmS9Pp\n" +
            "BOfWWgEsBgAKCRAHBzDWzGquJmIIAP4sQO7j7FH41KQf1E22SpbxiKSC2lK+9hxT\n" +
            "kv6divqdZgD/T91FUb9AenAJBLzyaTwReQSt/iEx1mxLi7QilaJCDA6YMwRjB6aq\n" +
            "FgkrBgEEAdpHDwEBB0D/8+N/bzvx2kZTrQ3fvGv6GTyBZGy1qqH9+70/orCegbQU\n" +
            "QiA8YkBwZ3BhaW5sZXNzLm9yZz6IjwQTFgoAQQUCYwemqgkQDmT2NIT1D4IWIQTH\n" +
            "zU3gfxyXLgTTOGAOZPY0hPUPggKeAQKbAQUWAgMBAAQLCQgHBRUKCQgLApkBAAAp\n" +
            "3wEA4Pj8MpGKBiwG/I2A26B6IDz0MZ/IiR204tWjh54ZgIYA/RYrxyfdmuKhEzMf\n" +
            "MA0a0juZ1euzxYPeNvgYJRjOnoUCuDgEYwemqhIKKwYBBAGXVQEFAQEHQPiGISsj\n" +
            "Hv/wd8eQXUxMFU2I1ex6c9LcDXKOHHvL4XB1AwEIB4h1BBgWCgAdBQJjB6aqAp4B\n" +
            "ApsMBRYCAwEABAsJCAcFFQoJCAsACgkQDmT2NIT1D4IdlQEA8cjOGf2X0D0v7gRg\n" +
            "wV6C8o7KaIjwqbRFjbw4v7dewT4BANjBU/KD+SgKG9l27t0pv7fzklWxUwehfIYR\n" +
            "veVegsEKuDMEYwemqhYJKwYBBAHaRw8BAQdAZA6ryWxnMEfhxhmfA8n54fgQXUE2\n" +
            "BwPobUGLfhjee8eI1QQYFgoAfQUCYwemqgKeAQKbAgUWAgMBAAQLCQgHBRUKCQgL\n" +
            "XyAEGRYKAAYFAmMHpqoACgkQB/5eyqSzV2hurwEAv0ODS93BTlgBXL6dDZ+6vO+y\n" +
            "emW6wH4RBZcrvQOhmpMBALhVrbS6L97HukL9B9QMSyP9Ir3QrBJihJNQjIcs/9UD\n" +
            "AAoJEA5k9jSE9Q+CAogA/jdAcbky2S6Ym39EqV8xCQKr7ddOKMzMUhGM65W6sAlP\n" +
            "AP99OZu3bNXsH79eJ8KmSpTaRH8meRgSaIve/6NgAmO2CpgzBGMHpqoWCSsGAQQB\n" +
            "2kcPAQEHQOdxRopw4vC2USLv4kqEVKNlAM+NkYomruNqsVlde9iutBRDIDxjQHBn\n" +
            "cGFpbmxlc3Mub3JnPoiPBBMWCgBBBQJjB6aqCRBUXcAjBoWYJBYhBJFl6D4X+Xm9\n" +
            "JjH+/VRdwCMGhZgkAp4BApsBBRYCAwEABAsJCAcFFQoJCAsCmQEAAAD4AQD9PvbC\n" +
            "y/SNXx62jnQmNHVXo/UDOmUqHymwHvm0MrKHeQEA06X5eLoHsttbRTvQt4NVYjdy\n" +
            "pDT4ySNvQCu6a5CiKg+4OARjB6aqEgorBgEEAZdVAQUBAQdAV1TW1qj0O2DGGBnR\n" +
            "y11gSj6uHhxOaGps2QE9asfp7QEDAQgHiHUEGBYKAB0FAmMHpqoCngECmwwFFgID\n" +
            "AQAECwkIBwUVCgkICwAKCRBUXcAjBoWYJIY9AQCVPseDfgRuCG7ygCmPtLO3Vp5j\n" +
            "ZcDF1fke/J3Z6LVAvQEA2bxaKgArPRrTlmCgM7iJSOBVyzryWZ7+lmbjLeqVxgi4\n" +
            "MwRjB6aqFgkrBgEEAdpHDwEBB0CCEWkyuz0HoWS63dinLk2VZJde4s4w0sQR9pPB\n" +
            "6wlwvIjVBBgWCgB9BQJjB6aqAp4BApsCBRYCAwEABAsJCAcFFQoJCAtfIAQZFgoA\n" +
            "BgUCYwemqgAKCRD9CgygdUb5mXWoAP0Zp5qSRFMJEghCgnZqcGIjlotGUc65uXv4\n" +
            "U5iqHfgEJAD/aAhA55MmlxIDXUkDMlKsy8WfhksLu6dfMkjJY2LYEAgACgkQVF3A\n" +
            "IwaFmCTV5wD9ErsC4w6ajM6PTGImtrK6IJEdMGajOwSGYWHiX9yaOI4BANdWby+h\n" +
            "Pr2snaTp6/NukIbg3D/YMXm+mM6119v7HJkO\n" +
            "=KVYs\n" +
            "-----END PGP PUBLIC KEY BLOCK-----";
    private static final OpenPgpFingerprint cert1fp = OpenPgpFingerprint.parse("76324A41CC19C0AA33B3C1F6070730D6CC6AAE26");
    private static final OpenPgpFingerprint cert2fp = OpenPgpFingerprint.parse("C7CD4DE07F1C972E04D338600E64F63484F50F82");
    private static final OpenPgpFingerprint cert3fp = OpenPgpFingerprint.parse("9165E83E17F979BD2631FEFD545DC02306859824");

    @Test
    public void encryptWithKeyFromStore() throws PGPException, IOException, BadDataException, InterruptedException, BadNameException {
        // In-Memory certificate store
        PGPainlessCertD certificateDirectory = PGPainlessCertD.inMemory();
        PGPCertificateStoreAdapter adapter = new PGPCertificateStoreAdapter(certificateDirectory);

        // Populate store
        PGPPublicKeyRingCollection certificates = PGPainless.readKeyRing().publicKeyRingCollection(CERT_COLLECTION);
        for (PGPPublicKeyRing cert : certificates) {
            certificateDirectory.insert(new ByteArrayInputStream(cert.getEncoded()), MergeCallbacks.mergeWithExisting());
        }

        // Encrypt message
        ByteArrayOutputStream ciphertextOut = new ByteArrayOutputStream();
        EncryptionStream encryptionStream = PGPainless.encryptAndOrSign()
                .onOutputStream(ciphertextOut)
                .withOptions(ProducerOptions.encrypt(
                        EncryptionOptions.encryptCommunications()
                                .addRecipient(adapter, cert2fp)));
        ByteArrayInputStream plaintext = new ByteArrayInputStream("Hello, World! This message is encrypted using a cert from a store!".getBytes());
        Streams.pipeAll(plaintext, encryptionStream);
        encryptionStream.close();

        // Get cert from store
        Certificate cert = adapter.getCertificate(cert2fp.toString());
        PGPPublicKeyRing publicKeys = PGPainless.readKeyRing().publicKeyRing(cert.getInputStream());

        // check if message was encrypted for cert
        assertTrue(encryptionStream.getResult().isEncryptedFor(publicKeys));
    }
}
