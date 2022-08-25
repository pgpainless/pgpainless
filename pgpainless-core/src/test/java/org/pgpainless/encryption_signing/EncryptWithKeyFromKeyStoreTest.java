// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.encryption_signing;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.util.io.Streams;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.certificate_store.MergeCallbacks;
import org.pgpainless.certificate_store.PGPainlessCertD;
import org.pgpainless.decryption_verification.ConsumerOptions;
import org.pgpainless.decryption_verification.DecryptionStream;
import org.pgpainless.decryption_verification.OpenPgpMetadata;
import org.pgpainless.key.OpenPgpFingerprint;
import org.pgpainless.key.protection.SecretKeyRingProtector;
import pgp.cert_d.PGPCertificateStoreAdapter;
import pgp.certificate_store.certificate.Certificate;
import pgp.certificate_store.exception.BadDataException;
import pgp.certificate_store.exception.BadNameException;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

import static org.junit.jupiter.api.Assertions.assertTrue;

public class EncryptWithKeyFromKeyStoreTest {

    // Collection of 3 keys (fingerprints below)
    private static final String KEY_COLLECTION = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
            "Version: BCPG v1.71\n" +
            "\n" +
            "lFgEYwerQBYJKwYBBAHaRw8BAQdAl3XjFMXQdmhMuFEIbE7IJUP1k+5utUT6IAW3\n" +
            "zlWguvQAAQDK7Qh5Q9EAB5cTh2OWsPeydfDqRmnuxlZjlwf4WWQLhRAltBRBIDxh\n" +
            "QHBncGFpbmxlc3Mub3JnPoiPBBMWCgBBBQJjB6tBCRBoj2Vso6FpsxYhBNqK9ZX8\n" +
            "QfcbxPJmCGiPZWyjoWmzAp4BApsBBRYCAwEABAsJCAcFFQoJCAsCmQEAACEaAP9P\n" +
            "49Q/E19vyx2rV8EjQd+XBFnDuYxBjw80ZVC0TaKJNgEAgWsQqcg/ARkG9XGxaE3X\n" +
            "IE9tFHh4wpjQhnK1Ta/wJAOcXQRjB6tBEgorBgEEAZdVAQUBAQdATJM1XKfKVF+C\n" +
            "B2/xrGU+F89Ir9viOut4sna4aWfvwHoDAQgHAAD/UN84yv5jxKsPgfw/XZCDwoey\n" +
            "Y69ompSiBuZjzOWrjegToIh1BBgWCgAdBQJjB6tBAp4BApsMBRYCAwEABAsJCAcF\n" +
            "FQoJCAsACgkQaI9lbKOhabP/PAEApov4hYuhIENq26z+w4s3A1gakN+gax54F7+M\n" +
            "YSUm16sBAPiuEdpVJOwTk3WMXKyLOYaVU3JstlP2H1ouguvYTt4CnFgEYwerQRYJ\n" +
            "KwYBBAHaRw8BAQdA5xpeGHNy9v+QUbl+Rs7Mx0c6D913gksW1eZ4Qeg31B0AAQCx\n" +
            "6b3P5lRBAraZstlRupymrt6vF2JpeJB8JOOQ+rdVYBJpiNUEGBYKAH0FAmMHq0EC\n" +
            "ngECmwIFFgIDAQAECwkIBwUVCgkIC18gBBkWCgAGBQJjB6tBAAoJENH9GnI3A/RM\n" +
            "IVMA/1GU9E+vA8bs0vJVDjp1ri3J4S7u+abwmlivDw8g8XCWAPwKWWfHLgJCsAHk\n" +
            "INuDgJdqbNPATFiXxH9FqYnOvWy6DAAKCRBoj2Vso6Fps884AP9D5ZOwuBEXyT/j\n" +
            "0G8CWBZ0lT14kRGFucjQi9kZStAuVgEA5cd3eUWofnekd/P6R3UgmvhVOqvxwUUg\n" +
            "Y3mEArH7+waUWARjB6tBFgkrBgEEAdpHDwEBB0BCYWjTs0pfBnKYgO0O07djiMSB\n" +
            "tUJVpUFo6zrVK92RgAAA/38G6IEK5rJs1OCusmmhHJk1vDu0hbesK7JH7dh75mVY\n" +
            "Ep20FEIgPGJAcGdwYWlubGVzcy5vcmc+iI8EExYKAEEFAmMHq0EJEAnsE6FTTHNl\n" +
            "FiEE2/L5HBba6IFDHu8cCewToVNMc2UCngECmwEFFgIDAQAECwkIBwUVCgkICwKZ\n" +
            "AQAAS7MBAI74uYLK7XR6oCwWYk7C6nwdgu3t478MaEpVHQz/9nEGAQCvJCYqqOd6\n" +
            "cAG6fwFaIJ3h99/Y5o2NaiN17S2zOXEZDJxdBGMHq0ESCisGAQQBl1UBBQEBB0BU\n" +
            "EjXQCT4xwJryksXsMLaFo43pFTwWaTzduiWgCy2KMgMBCAcAAP9lXlnMYtBfXpgH\n" +
            "doUZZk3cvWBOH3awc12V3jZSLtSE8BAJiHUEGBYKAB0FAmMHq0ECngECmwwFFgID\n" +
            "AQAECwkIBwUVCgkICwAKCRAJ7BOhU0xzZf5lAQDOgzMhqg3fE8Hg4Hbt4+B0fAD0\n" +
            "kp6EJgsKRWT7KbZ0SQD/aVGFv7VRVqiiqOT/YMQKBBwHnq/CGJqxUwUmavBMRAqc\n" +
            "WARjB6tBFgkrBgEEAdpHDwEBB0A5kv3bpsnlxs2LrAzeBx4RgtXQNBhGRhzko1to\n" +
            "4q+ebQAA/1SU1hvrqd9gNmcc4wff1iwJ1dnqnrbGbO1Yz9rYZjXRE4iI1QQYFgoA\n" +
            "fQUCYwerQQKeAQKbAgUWAgMBAAQLCQgHBRUKCQgLXyAEGRYKAAYFAmMHq0EACgkQ\n" +
            "pYWdiAVpxGRW4AD+Lade9kJrvcBMSq8EERhYTH6DFka4eMgFB76kH31WmpQA+gOU\n" +
            "7kwqKmtyVsXVgCLGMcdTvbZr+73C5m8R7LsdY5kEAAoJEAnsE6FTTHNl7BAA/2v8\n" +
            "Wzfmg1OO6IWCohmmNgF4rIDBW8Q9s3+1I/mWlMyjAP9YGR+fnN/YOQrlSG9UiXE5\n" +
            "fGwUhaPB0LEGWp0wmmQYA5RYBGMHq0EWCSsGAQQB2kcPAQEHQI8C53+C8crLCQ48\n" +
            "OKQa1dEKc8XWQSA6Ckg5j73tOJRLAAD/VRvioGU2M9G6+eKTn68mBVZ8G512HELr\n" +
            "apK9M5UFGUMPXLQUQyA8Y0BwZ3BhaW5sZXNzLm9yZz6IjwQTFgoAQQUCYwerQQkQ\n" +
            "ommXHYx1l94WIQQp+Mrw86EV1myUgUKiaZcdjHWX3gKeAQKbAQUWAgMBAAQLCQgH\n" +
            "BRUKCQgLApkBAAAQ5wEAvahnnRuwY+Y7EPSQG+sqhsdvSTumleYPtEOnHfKctpkA\n" +
            "/iaTp4OoUw/RtyWUAk8MLN47CAW5wwhFUbVfZOaS88wMnF0EYwerQRIKKwYBBAGX\n" +
            "VQEFAQEHQNz/s68ZGUBfDmMz510cFgHz+mAdC2nXeE4hHKV/HIVsAwEIBwAA/1HB\n" +
            "vRl84B8r/PY+5j/X6A+4J08QB/vd5wIHVdkrX+xQELGIdQQYFgoAHQUCYwerQQKe\n" +
            "AQKbDAUWAgMBAAQLCQgHBRUKCQgLAAoJEKJplx2MdZfeqzYA/jLtjRmy42MCOxnF\n" +
            "3A95WZIDoEohFU0QAeE/yVTLGoDTAP4xhTznleABK7VbD9GJXfD6DkEC749tOsST\n" +
            "eYO/GOxKDpxYBGMHq0EWCSsGAQQB2kcPAQEHQFnvyWSgOv4gn3Ch3RY74pRg+7hX\n" +
            "OBJAf6ybwvx9t4olAAEAwYG1CL0JozVD1216yrENkP8La132O1MI28kqMsoF6FcP\n" +
            "I4jVBBgWCgB9BQJjB6tBAp4BApsCBRYCAwEABAsJCAcFFQoJCAtfIAQZFgoABgUC\n" +
            "YwerQQAKCRB8jJGVps/ENgz7AP9ZMENJH+rIKMjynb9WPBlvJ8yJ9dMhzCxcssxg\n" +
            "EVZYXAEA5ZsE5xJLQC/cVMGFvqaQ8iPo5jhDZpQJ8RCVlb8XzQwACgkQommXHYx1\n" +
            "l96SkgD/f0FYkK4yB8FWuntJ3n0FUfE31wDwpxvvpvP+o3d2GB4BAP9LRKBXMwj4\n" +
            "jzJc4ViKmwiNJAPttDQCpYjzJT7LUKAA\n" +
            "=EAvh\n" +
            "-----END PGP PRIVATE KEY BLOCK-----";

    // Collection of 3 certificates (fingerprints below)
    private static final String CERT_COLLECTION = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
            "Version: BCPG v1.71\n" +
            "\n" +
            "mDMEYwerQBYJKwYBBAHaRw8BAQdAl3XjFMXQdmhMuFEIbE7IJUP1k+5utUT6IAW3\n" +
            "zlWguvS0FEEgPGFAcGdwYWlubGVzcy5vcmc+iI8EExYKAEEFAmMHq0EJEGiPZWyj\n" +
            "oWmzFiEE2or1lfxB9xvE8mYIaI9lbKOhabMCngECmwEFFgIDAQAECwkIBwUVCgkI\n" +
            "CwKZAQAAIRoA/0/j1D8TX2/LHatXwSNB35cEWcO5jEGPDzRlULRNook2AQCBaxCp\n" +
            "yD8BGQb1cbFoTdcgT20UeHjCmNCGcrVNr/AkA7g4BGMHq0ESCisGAQQBl1UBBQEB\n" +
            "B0BMkzVcp8pUX4IHb/GsZT4Xz0iv2+I663iydrhpZ+/AegMBCAeIdQQYFgoAHQUC\n" +
            "YwerQQKeAQKbDAUWAgMBAAQLCQgHBRUKCQgLAAoJEGiPZWyjoWmz/zwBAKaL+IWL\n" +
            "oSBDatus/sOLNwNYGpDfoGseeBe/jGElJterAQD4rhHaVSTsE5N1jFysizmGlVNy\n" +
            "bLZT9h9aLoLr2E7eArgzBGMHq0EWCSsGAQQB2kcPAQEHQOcaXhhzcvb/kFG5fkbO\n" +
            "zMdHOg/dd4JLFtXmeEHoN9QdiNUEGBYKAH0FAmMHq0ECngECmwIFFgIDAQAECwkI\n" +
            "BwUVCgkIC18gBBkWCgAGBQJjB6tBAAoJENH9GnI3A/RMIVMA/1GU9E+vA8bs0vJV\n" +
            "Djp1ri3J4S7u+abwmlivDw8g8XCWAPwKWWfHLgJCsAHkINuDgJdqbNPATFiXxH9F\n" +
            "qYnOvWy6DAAKCRBoj2Vso6Fps884AP9D5ZOwuBEXyT/j0G8CWBZ0lT14kRGFucjQ\n" +
            "i9kZStAuVgEA5cd3eUWofnekd/P6R3UgmvhVOqvxwUUgY3mEArH7+waYMwRjB6tB\n" +
            "FgkrBgEEAdpHDwEBB0BCYWjTs0pfBnKYgO0O07djiMSBtUJVpUFo6zrVK92RgLQU\n" +
            "QiA8YkBwZ3BhaW5sZXNzLm9yZz6IjwQTFgoAQQUCYwerQQkQCewToVNMc2UWIQTb\n" +
            "8vkcFtrogUMe7xwJ7BOhU0xzZQKeAQKbAQUWAgMBAAQLCQgHBRUKCQgLApkBAABL\n" +
            "swEAjvi5gsrtdHqgLBZiTsLqfB2C7e3jvwxoSlUdDP/2cQYBAK8kJiqo53pwAbp/\n" +
            "AVogneH339jmjY1qI3XtLbM5cRkMuDgEYwerQRIKKwYBBAGXVQEFAQEHQFQSNdAJ\n" +
            "PjHAmvKSxewwtoWjjekVPBZpPN26JaALLYoyAwEIB4h1BBgWCgAdBQJjB6tBAp4B\n" +
            "ApsMBRYCAwEABAsJCAcFFQoJCAsACgkQCewToVNMc2X+ZQEAzoMzIaoN3xPB4OB2\n" +
            "7ePgdHwA9JKehCYLCkVk+ym2dEkA/2lRhb+1UVaooqjk/2DECgQcB56vwhiasVMF\n" +
            "JmrwTEQKuDMEYwerQRYJKwYBBAHaRw8BAQdAOZL926bJ5cbNi6wM3gceEYLV0DQY\n" +
            "RkYc5KNbaOKvnm2I1QQYFgoAfQUCYwerQQKeAQKbAgUWAgMBAAQLCQgHBRUKCQgL\n" +
            "XyAEGRYKAAYFAmMHq0EACgkQpYWdiAVpxGRW4AD+Lade9kJrvcBMSq8EERhYTH6D\n" +
            "Fka4eMgFB76kH31WmpQA+gOU7kwqKmtyVsXVgCLGMcdTvbZr+73C5m8R7LsdY5kE\n" +
            "AAoJEAnsE6FTTHNl7BAA/2v8Wzfmg1OO6IWCohmmNgF4rIDBW8Q9s3+1I/mWlMyj\n" +
            "AP9YGR+fnN/YOQrlSG9UiXE5fGwUhaPB0LEGWp0wmmQYA5gzBGMHq0EWCSsGAQQB\n" +
            "2kcPAQEHQI8C53+C8crLCQ48OKQa1dEKc8XWQSA6Ckg5j73tOJRLtBRDIDxjQHBn\n" +
            "cGFpbmxlc3Mub3JnPoiPBBMWCgBBBQJjB6tBCRCiaZcdjHWX3hYhBCn4yvDzoRXW\n" +
            "bJSBQqJplx2MdZfeAp4BApsBBRYCAwEABAsJCAcFFQoJCAsCmQEAABDnAQC9qGed\n" +
            "G7Bj5jsQ9JAb6yqGx29JO6aV5g+0Q6cd8py2mQD+JpOng6hTD9G3JZQCTwws3jsI\n" +
            "BbnDCEVRtV9k5pLzzAy4OARjB6tBEgorBgEEAZdVAQUBAQdA3P+zrxkZQF8OYzPn\n" +
            "XRwWAfP6YB0Ladd4TiEcpX8chWwDAQgHiHUEGBYKAB0FAmMHq0ECngECmwwFFgID\n" +
            "AQAECwkIBwUVCgkICwAKCRCiaZcdjHWX3qs2AP4y7Y0ZsuNjAjsZxdwPeVmSA6BK\n" +
            "IRVNEAHhP8lUyxqA0wD+MYU855XgASu1Ww/RiV3w+g5BAu+PbTrEk3mDvxjsSg64\n" +
            "MwRjB6tBFgkrBgEEAdpHDwEBB0BZ78lkoDr+IJ9wod0WO+KUYPu4VzgSQH+sm8L8\n" +
            "fbeKJYjVBBgWCgB9BQJjB6tBAp4BApsCBRYCAwEABAsJCAcFFQoJCAtfIAQZFgoA\n" +
            "BgUCYwerQQAKCRB8jJGVps/ENgz7AP9ZMENJH+rIKMjynb9WPBlvJ8yJ9dMhzCxc\n" +
            "ssxgEVZYXAEA5ZsE5xJLQC/cVMGFvqaQ8iPo5jhDZpQJ8RCVlb8XzQwACgkQommX\n" +
            "HYx1l96SkgD/f0FYkK4yB8FWuntJ3n0FUfE31wDwpxvvpvP+o3d2GB4BAP9LRKBX\n" +
            "Mwj4jzJc4ViKmwiNJAPttDQCpYjzJT7LUKAA\n" +
            "=WaRm\n" +
            "-----END PGP PUBLIC KEY BLOCK-----";
    private static final OpenPgpFingerprint cert1fp = OpenPgpFingerprint.parse("DA8AF595FC41F71BC4F26608688F656CA3A169B3");
    private static final OpenPgpFingerprint cert2fp = OpenPgpFingerprint.parse("DBF2F91C16DAE881431EEF1C09EC13A1534C7365");
    private static final OpenPgpFingerprint cert3fp = OpenPgpFingerprint.parse("29F8CAF0F3A115D66C948142A269971D8C7597DE");

    @Test
    public void encryptWithCertFromCertificateStore() throws PGPException, IOException, BadDataException, InterruptedException, BadNameException {
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

    @Test
    public void verifyWithCertFromCertificateStore()
            throws PGPException, IOException, BadDataException, InterruptedException, BadNameException {
        // In-Memory certificate store
        PGPainlessCertD certificateDirectory = PGPainlessCertD.inMemory();
        PGPCertificateStoreAdapter adapter = new PGPCertificateStoreAdapter(certificateDirectory);

        // Populate store
        PGPPublicKeyRingCollection certificates = PGPainless.readKeyRing().publicKeyRingCollection(CERT_COLLECTION);
        for (PGPPublicKeyRing cert : certificates) {
            certificateDirectory.insert(new ByteArrayInputStream(cert.getEncoded()), MergeCallbacks.mergeWithExisting());
        }

        // Prepare keys
        OpenPgpFingerprint cryptFp = cert3fp;
        OpenPgpFingerprint signFp = cert1fp;
        PGPSecretKeyRingCollection secretKeys = PGPainless.readKeyRing().secretKeyRingCollection(KEY_COLLECTION);
        PGPSecretKeyRing signingKey = secretKeys.getSecretKeyRing(signFp.getKeyId());
        PGPSecretKeyRing decryptionKey = secretKeys.getSecretKeyRing(cryptFp.getKeyId());
        SecretKeyRingProtector protector = SecretKeyRingProtector.unprotectedKeys();

        // Encrypt and sign message
        ByteArrayInputStream plaintextIn = new ByteArrayInputStream(
                "This message was encrypted with a cert from a store and gets verified with a cert from a store as well".getBytes());
        ByteArrayOutputStream ciphertext = new ByteArrayOutputStream();
        EncryptionStream encryptionStream = PGPainless.encryptAndOrSign()
                .onOutputStream(ciphertext)
                .withOptions(
                        ProducerOptions.signAndEncrypt(
                                EncryptionOptions.encryptCommunications()
                                        .addRecipient(adapter, cryptFp),
                                SigningOptions.get()
                                        .addSignature(protector, signingKey)
                        ));
        Streams.pipeAll(plaintextIn, encryptionStream);
        encryptionStream.close();

        // Prepare ciphertext for decryption
        ByteArrayInputStream ciphertextIn = new ByteArrayInputStream(ciphertext.toByteArray());
        ByteArrayOutputStream plaintextOut = new ByteArrayOutputStream();
        // Decrypt and verify
        DecryptionStream decryptionStream = PGPainless.decryptAndOrVerify()
                .onInputStream(ciphertextIn)
                .withOptions(
                        new ConsumerOptions()
                                .addDecryptionKey(decryptionKey, protector)
                                .addVerificationCerts(adapter));
        Streams.pipeAll(decryptionStream, plaintextOut);
        decryptionStream.close();

        // Check that message can be decrypted and is verified
        OpenPgpMetadata result = decryptionStream.getResult();
        assertTrue(result.isEncrypted());
        assertTrue(result.isVerified());
        assertTrue(result.containsVerifiedSignatureFrom(signFp));
    }
}
