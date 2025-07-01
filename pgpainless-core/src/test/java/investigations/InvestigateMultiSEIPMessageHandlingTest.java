// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package investigations;

import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Date;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.api.OpenPGPImplementation;
import org.bouncycastle.openpgp.api.OpenPGPKey;
import org.bouncycastle.openpgp.operator.PGPDataEncryptorBuilder;
import org.bouncycastle.util.io.Streams;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.EncryptionPurpose;
import org.pgpainless.algorithm.HashAlgorithm;
import org.pgpainless.algorithm.SignatureType;
import org.pgpainless.decryption_verification.ConsumerOptions;
import org.pgpainless.decryption_verification.DecryptionStream;
import org.pgpainless.exception.MalformedOpenPgpMessageException;
import org.pgpainless.key.info.KeyRingInfo;
import org.pgpainless.key.protection.UnlockSecretKey;
import org.pgpainless.util.Passphrase;

/**
 * This test is used to investigate, how messages of the form
 * {@code
 * SKESK for key 1
 * SEIP with sig by key 1
 * SKESK for key 1
 * SEIP with sig by key 2
 * }
 * are handled.
 */
public class InvestigateMultiSEIPMessageHandlingTest {

    private static final String KEY1 = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
            "Version: PGPainless\n" +
            "Comment: 9ADC EA42 5A77 175D CE89  A64C 8844 ADB3 5B25 32B3\n" +
            "Comment: A <a@pgpainless.org>\n" +
            "\n" +
            "lFgEYSLIYxYJKwYBBAHaRw8BAQdAcRpUuEQpAz6MZXyI1pYxrn3BYDM+nQ82rqJ8\n" +
            "UYotnGAAAQCUJztoX7z8C2TkDhiwNE3HA1YJn1oH0ZqYARhMD5fXPgxstBRBIDxh\n" +
            "QHBncGFpbmxlc3Mub3JnPoh4BBMWCgAgBQJhIshjAhsBBRYCAwEABAsJCAcFFQoJ\n" +
            "CAsCHgECGQEACgkQiESts1slMrO3UQEAhawYA+P05pXx/IXZw7iYVZgycNJgdrpl\n" +
            "AGE/pqkKz6AA/jZ4BQQQiS76H2n1w8jbcxfjOu8OTeOU7vPiZ0s6On0PnF0EYSLI\n" +
            "YxIKKwYBBAGXVQEFAQEHQCU/tyOZyPSdceSO1tuPMODBLigOWv3kz3S6rdoBdngL\n" +
            "AwEIBwAA/3cmc8CxylajLeReu5z6mB+LYXQFIZlLQugQxFlUd34gD+SIdQQYFgoA\n" +
            "HQUCYSLIYwIbDAUWAgMBAAQLCQgHBRUKCQgLAh4BAAoJEIhErbNbJTKzO4kA/2P0\n" +
            "gfF4U5HYgrkvpc60U8XoU4i1wn7nuHSQdOCATBxhAQDamNiJkFuwVbdr3Sm9wPj7\n" +
            "e90hAGS5S8MYtvgqohWgApxYBGEiyGMWCSsGAQQB2kcPAQEHQB+AsjQrdFYb3FOm\n" +
            "8gr00Fr4jGO4l6JnZvcjLTLNPQ9ZAAD/b4yjw0uL3YOvLFoEfqc//Ys+ch818dnY\n" +
            "207tl2vqBUURrYjVBBgWCgB9BQJhIshjAhsCBRYCAwEABAsJCAcFFQoJCAsCHgFf\n" +
            "IAQZFgoABgUCYSLIYwAKCRCvyvLofXqtnBTLAP4tD6zt0pYuCsoESOcnKzAAnVAS\n" +
            "UFQtB+h3kusS9XkQ/wD9G5dWb83n0y0kjxk5Dx8JSxExYTfr1lHW80HbO8JUrQ0A\n" +
            "CgkQiESts1slMrNDSAD+JFfqSonAxBIVVjm+eUtusHVSWEHhL5t2e11PBGX4FlMB\n" +
            "AIS4R9MQjofP/wK0bv/s4EAemt0pLjl3UBSj1hyOo/QN\n" +
            "=2qDX\n" +
            "-----END PGP PRIVATE KEY BLOCK-----";
    private static final String KEY2 = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
            "Version: PGPainless\n" +
            "Comment: E224 69A0 9667 85AE 3E54  4258 37C9 616B 54C2 6E5B\n" +
            "Comment: B <b@pgpainless.org>\n" +
            "\n" +
            "lFgEYSLIYxYJKwYBBAHaRw8BAQdAHON5KoqLFv8ZwWUD5b4OVCvg5NTireZ5Xon9\n" +
            "9o5kQs4AAP0Tv9E98dv79aEQkRNT0y0ARXMHrPnrDZlVeTwSoYZmnRB8tBRCIDxi\n" +
            "QHBncGFpbmxlc3Mub3JnPoh4BBMWCgAgBQJhIshjAhsBBRYCAwEABAsJCAcFFQoJ\n" +
            "CAsCHgECGQEACgkQN8lha1TCblvvZwD/R98IEHgrKA1QcTAOTdAeZr3N2JbfiI8S\n" +
            "RCnRSZyxZA8BAJflL0yV0RkEawiLYFXHdr6MmXvDD8vcWtRkvudyc1QJnF0EYSLI\n" +
            "YxIKKwYBBAGXVQEFAQEHQJITVbNYNfGslnFs6pkkGsMOoe+kK+tKjJ1ECJ2enpct\n" +
            "AwEIBwAA/2HEXwf73zKsND8TQQpwGVyelSB2E5kvvTYEMICOalGoDTSIdQQYFgoA\n" +
            "HQUCYSLIYwIbDAUWAgMBAAQLCQgHBRUKCQgLAh4BAAoJEDfJYWtUwm5bWjEBAMnI\n" +
            "PayRwnuRNrjxUMesOOrFXi8So4cFTbf0VWT2wmrvAPwOAk0pcoikwP5gWSVhlEHp\n" +
            "A2qmM5j6MiJzwb8o2j7DDpxYBGEiyGMWCSsGAQQB2kcPAQEHQHvKk+Nb1ffEoipo\n" +
            "RsozdQAplIqGs++M0DcdR85pFWWDAAEAqqEYtlZqCDGXrndD495QJvc5bBkrRyxb\n" +
            "K0ESndh27ZIN34jVBBgWCgB9BQJhIshjAhsCBRYCAwEABAsJCAcFFQoJCAsCHgFf\n" +
            "IAQZFgoABgUCYSLIYwAKCRCWR2MKq82PQQ0bAQCbWxtyDCDMakDnD1wdix1bZ5gv\n" +
            "873RNdo4LwluVId1RwD+L+meOEk66U53A6GBRlyo639Mnhqyjkssk43siDVI4AkA\n" +
            "CgkQN8lha1TCblvsvwEA/K72P5m6B0trzjPqPRdke42oeLMfK7k0jZaPcd72YuQA\n" +
            "/3YNr1L5pHVWoIRhOs/4lkic6P7OCiuMWRpKDt6ZZusD\n" +
            "=0mZj\n" +
            "-----END PGP PRIVATE KEY BLOCK-----\n";
    private static final String MESSAGE = "-----BEGIN PGP MESSAGE-----\n" +
            "Version: BCPG v1.69\n" +
            "\n" +
            "hF4DrtaS0Fxq0aMSAQdAbzk04kiO9cpqeEFIG5gDrtfUg/roteHfHrAj4z48NFUw\n" +
            "KXxtZ4Fyy/LGEenKAHDr8gBNWD7jyQSRlC8YFVxwVqT4Kk52+2M5U6jf6XDKMJxA\n" +
            "0q4BdbOTMZvZ+CSdJNkRd88frSCyJwrYCmaasmfOsZGousS5QiL7u/ChbhBAKyfB\n" +
            "4gkYrVgG1Z43ZvsVe4TnUYitAdM1KEMSwGsbfN5qZrJu0f/XwCZjOdl3wCOFMFs9\n" +
            "AQ51WRdd8TA20XAyeiBRDbPe3tZwQgPOC/1+Qw6AYzoWpCgLFQQWCOsboNj8xqa0\n" +
            "aPUDnm9pR/dAe1vJogZD/V9W4fKwvn+tJsmCQSuU2mCEXgOu1pLQXGrRoxIBB0DS\n" +
            "6tvqhqsOD2rrIQuKkJVbsWFWIW59PC50J8+BfPqJczBi2L7HTUy2nsx9tsuRi8Cd\n" +
            "/qGHgVxs6cHZGWN7IeHuiD6jciFSXvJR+RrkJQpgpAnSqQEXJmHi4IJfJhVDNwt0\n" +
            "4sfLhTW3seQZUu/uAp4wMO3izP7yfErNSX2MoP25AxtrR10ImmMK6YIHJyEb3j4L\n" +
            "IZHjNkHcthuPVgfDCmmRLAJYTLoXKfLAmL3M/d+hIzoudozKcnc4xNZ5ac9De8Pf\n" +
            "YMnkq1n/bnFAfgc12SeAHSqSvnqVNqgb59DItSj3bC8GMnSQ1jkqODtYPdiRd2hE\n" +
            "osUF5+pq7SnxlPc=\n" +
            "=kvka\n" +
            "-----END PGP MESSAGE-----";

    private static final String data1 = "Hello, World!\n";
    private static final String data2 = "Appendix\n";

    @Test
    public void generateTestMessage() throws PGPException, IOException {
        PGPSecretKeyRing ring1 = PGPainless.readKeyRing().secretKeyRing(KEY1);
        KeyRingInfo info1 = PGPainless.inspectKeyRing(ring1);
        PGPPublicKey cryptKey1 = info1.getEncryptionSubkeys(EncryptionPurpose.ANY).get(0).getPGPPublicKey();
        PGPSecretKey signKey1 = ring1.getSecretKey(info1.getSigningSubkeys().get(0).getKeyIdentifier());
        PGPSecretKeyRing ring2 = PGPainless.readKeyRing().secretKeyRing(KEY2);
        KeyRingInfo info2 = PGPainless.inspectKeyRing(ring2);
        PGPSecretKey signKey2 = ring2.getSecretKey(info2.getSigningSubkeys().get(0).getKeyIdentifier());

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ArmoredOutputStream armorOut = new ArmoredOutputStream(out);

        PGPDataEncryptorBuilder cryptBuilder = OpenPGPImplementation.getInstance().pgpDataEncryptorBuilder(SymmetricKeyAlgorithmTags.AES_256);
        cryptBuilder.setWithIntegrityPacket(true);

        encryptAndSign(cryptKey1, signKey1, armorOut, data1.getBytes(StandardCharsets.UTF_8));
        encryptAndSign(cryptKey1, signKey2, armorOut, data2.getBytes(StandardCharsets.UTF_8));

        armorOut.close();

        // CHECKSTYLE:OFF
        System.out.println(out);
        // CHECKSTYLE:ON
    }

    private void encryptAndSign(PGPPublicKey cryptKey, PGPSecretKey signKey, ArmoredOutputStream armorOut, byte[] data) throws IOException, PGPException {

        PGPDataEncryptorBuilder cryptBuilder = OpenPGPImplementation.getInstance().pgpDataEncryptorBuilder(SymmetricKeyAlgorithmTags.AES_256);
        cryptBuilder.setWithIntegrityPacket(true);

        PGPEncryptedDataGenerator cryptGen = new PGPEncryptedDataGenerator(cryptBuilder);
        cryptGen.addMethod(OpenPGPImplementation.getInstance().publicKeyKeyEncryptionMethodGenerator(cryptKey));
        OutputStream cryptStream = cryptGen.open(armorOut, new byte[512]);

        PGPSignatureGenerator sigGen = new PGPSignatureGenerator(OpenPGPImplementation.getInstance()
                .pgpContentSignerBuilder(signKey.getPublicKey().getAlgorithm(), HashAlgorithm.SHA512.getAlgorithmId()),
                signKey.getPublicKey());
        sigGen.init(SignatureType.BINARY_DOCUMENT.getCode(), UnlockSecretKey
                .unlockSecretKey(signKey, (Passphrase) null));

        sigGen.generateOnePassVersion(false).encode(cryptStream);

        PGPLiteralDataGenerator litGen = new PGPLiteralDataGenerator();
        OutputStream litOut = litGen.open(cryptStream, PGPLiteralDataGenerator.BINARY, "", new Date(), new byte[512]);

        for (byte b : data) {
            litOut.write(b);
            sigGen.update(b);
        }

        litOut.flush();
        litOut.close();

        sigGen.generate().encode(cryptStream);
        cryptStream.flush();
        cryptStream.close();
    }

    @Test
    public void testDecryptAndVerifyDetectsAppendedSEIPData() throws IOException, PGPException {
        PGPainless api = PGPainless.getInstance();
        OpenPGPKey ring1 = api.readKey().parseKey(KEY1);
        OpenPGPKey ring2 = api.readKey().parseKey(KEY2);

        ConsumerOptions options = ConsumerOptions.get()
                .addVerificationCert(ring2)
                .addVerificationCert(ring2)
                        .addDecryptionKey(ring1);

        DecryptionStream decryptionStream = api.processMessage()
                .onInputStream(new ByteArrayInputStream(MESSAGE.getBytes(StandardCharsets.UTF_8)))
                .withOptions(options);

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        assertThrows(MalformedOpenPgpMessageException.class, () -> Streams.pipeAll(decryptionStream, out));
    }
}
