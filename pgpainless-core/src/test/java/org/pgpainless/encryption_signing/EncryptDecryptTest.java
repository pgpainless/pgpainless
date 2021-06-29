/*
 * Copyright 2018 Paul Schaub.
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
package org.pgpainless.encryption_signing;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.Charset;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.util.Set;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.util.io.Streams;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.DocumentSignatureType;
import org.pgpainless.algorithm.KeyFlag;
import org.pgpainless.algorithm.SymmetricKeyAlgorithm;
import org.pgpainless.decryption_verification.ConsumerOptions;
import org.pgpainless.decryption_verification.DecryptionStream;
import org.pgpainless.decryption_verification.OpenPgpMetadata;
import org.pgpainless.implementation.ImplementationFactory;
import org.pgpainless.key.SubkeyIdentifier;
import org.pgpainless.key.TestKeys;
import org.pgpainless.key.generation.KeySpec;
import org.pgpainless.key.generation.type.KeyType;
import org.pgpainless.key.generation.type.elgamal.ElGamal;
import org.pgpainless.key.generation.type.elgamal.ElGamalLength;
import org.pgpainless.key.generation.type.rsa.RsaLength;
import org.pgpainless.key.protection.SecretKeyRingProtector;
import org.pgpainless.key.protection.UnprotectedKeysProtector;
import org.pgpainless.key.util.KeyRingUtils;
import org.pgpainless.util.ArmoredOutputStreamFactory;

public class EncryptDecryptTest {

    // Don't use StandardCharsets.UTF_8 because of Android API level.
    private static final Charset UTF8 = Charset.forName("UTF-8");

    private static final String testMessage =
            "Ah, Juliet, if the measure of thy joy\n" +
                    "Be heaped like mine, and that thy skill be more\n" +
                    "To blazon it, then sweeten with thy breath\n" +
                    "This neighbor air, and let rich music’s tongue\n" +
                    "Unfold the imagined happiness that both\n" +
                    "Receive in either by this dear encounter.";

    @ParameterizedTest
    @MethodSource("org.pgpainless.util.TestUtil#provideImplementationFactories")
    public void freshKeysRsaToElGamalTest(ImplementationFactory implementationFactory)
            throws PGPException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, IOException {
        ImplementationFactory.setFactoryImplementation(implementationFactory);
        PGPSecretKeyRing sender = PGPainless.generateKeyRing().simpleRsaKeyRing("romeo@montague.lit", RsaLength._3072);
        PGPSecretKeyRing recipient = PGPainless.generateKeyRing()
                .withSubKey(KeySpec.getBuilder(ElGamal.withLength(ElGamalLength._3072)).withKeyFlags(KeyFlag.ENCRYPT_STORAGE, KeyFlag.ENCRYPT_COMMS).withDefaultAlgorithms())
                .withPrimaryKey(KeySpec.getBuilder(KeyType.RSA(RsaLength._4096)).withKeyFlags(KeyFlag.SIGN_DATA, KeyFlag.CERTIFY_OTHER).withDefaultAlgorithms())
                .withPrimaryUserId("juliet@capulet.lit").withoutPassphrase().build();

        encryptDecryptForSecretKeyRings(sender, recipient);
    }

    @ParameterizedTest
    @MethodSource("org.pgpainless.util.TestUtil#provideImplementationFactories")
    public void freshKeysRsaToRsaTest(ImplementationFactory implementationFactory)
            throws PGPException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, IOException {
        ImplementationFactory.setFactoryImplementation(implementationFactory);
        PGPSecretKeyRing sender = PGPainless.generateKeyRing().simpleRsaKeyRing("romeo@montague.lit", RsaLength._3072);
        PGPSecretKeyRing recipient = PGPainless.generateKeyRing().simpleRsaKeyRing("juliet@capulet.lit", RsaLength._3072);

        encryptDecryptForSecretKeyRings(sender, recipient);
    }

    @ParameterizedTest
    @MethodSource("org.pgpainless.util.TestUtil#provideImplementationFactories")
    public void freshKeysEcToEcTest(ImplementationFactory implementationFactory)
            throws IOException, PGPException, NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        ImplementationFactory.setFactoryImplementation(implementationFactory);
        PGPSecretKeyRing sender = PGPainless.generateKeyRing().simpleEcKeyRing("romeo@montague.lit");
        PGPSecretKeyRing recipient = PGPainless.generateKeyRing().simpleEcKeyRing("juliet@capulet.lit");

        encryptDecryptForSecretKeyRings(sender, recipient);
    }

    @ParameterizedTest
    @MethodSource("org.pgpainless.util.TestUtil#provideImplementationFactories")
    public void freshKeysEcToRsaTest(ImplementationFactory implementationFactory)
            throws PGPException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, IOException {
        ImplementationFactory.setFactoryImplementation(implementationFactory);
        PGPSecretKeyRing sender = PGPainless.generateKeyRing().simpleEcKeyRing("romeo@montague.lit");
        PGPSecretKeyRing recipient = PGPainless.generateKeyRing().simpleRsaKeyRing("juliet@capulet.lit", RsaLength._3072);

        encryptDecryptForSecretKeyRings(sender, recipient);
    }

    @ParameterizedTest
    @MethodSource("org.pgpainless.util.TestUtil#provideImplementationFactories")
    public void freshKeysRsaToEcTest(ImplementationFactory implementationFactory)
            throws PGPException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, IOException {
        ImplementationFactory.setFactoryImplementation(implementationFactory);
        PGPSecretKeyRing sender = PGPainless.generateKeyRing().simpleRsaKeyRing("romeo@montague.lit", RsaLength._3072);
        PGPSecretKeyRing recipient = PGPainless.generateKeyRing().simpleEcKeyRing("juliet@capulet.lit");

        encryptDecryptForSecretKeyRings(sender, recipient);
    }

    @ParameterizedTest
    @MethodSource("org.pgpainless.util.TestUtil#provideImplementationFactories")
    public void existingRsaKeysTest(ImplementationFactory implementationFactory) throws IOException, PGPException {
        ImplementationFactory.setFactoryImplementation(implementationFactory);
        PGPSecretKeyRing sender = TestKeys.getJulietSecretKeyRing();
        PGPSecretKeyRing recipient = TestKeys.getRomeoSecretKeyRing();

        encryptDecryptForSecretKeyRings(sender, recipient);
    }

    private void encryptDecryptForSecretKeyRings(PGPSecretKeyRing senderSec, PGPSecretKeyRing recipientSec)
            throws PGPException, IOException {

        PGPPublicKeyRing recipientPub = KeyRingUtils.publicKeyRingFrom(recipientSec);
        PGPPublicKeyRing senderPub = KeyRingUtils.publicKeyRingFrom(senderSec);

        SecretKeyRingProtector keyDecryptor = new UnprotectedKeysProtector();

        byte[] secretMessage = testMessage.getBytes(UTF8);

        ByteArrayOutputStream envelope = new ByteArrayOutputStream();

        EncryptionStream encryptor = PGPainless.encryptAndOrSign()
                .onOutputStream(envelope)
                .withOptions(ProducerOptions.signAndEncrypt(
                        EncryptionOptions.encryptCommunications().addRecipient(recipientPub),
                        new SigningOptions().addInlineSignature(keyDecryptor, senderSec, DocumentSignatureType.BINARY_DOCUMENT)
                ));

        Streams.pipeAll(new ByteArrayInputStream(secretMessage), encryptor);
        encryptor.close();
        byte[] encryptedSecretMessage = envelope.toByteArray();

        EncryptionResult encryptionResult = encryptor.getResult();

        assertFalse(encryptionResult.getRecipients().isEmpty());
        for (SubkeyIdentifier encryptionKey : encryptionResult.getRecipients()) {
            assertTrue(KeyRingUtils.keyRingContainsKeyWithId(recipientPub, encryptionKey.getKeyId()));
        }

        assertEquals(SymmetricKeyAlgorithm.AES_256, encryptionResult.getEncryptionAlgorithm());

        // Juliet trieth to comprehend Romeos words

        ByteArrayInputStream envelopeIn = new ByteArrayInputStream(encryptedSecretMessage);
        DecryptionStream decryptor = PGPainless.decryptAndOrVerify()
                .onInputStream(envelopeIn)
                .withOptions(new ConsumerOptions()
                        .addDecryptionKey(recipientSec, keyDecryptor)
                        .addVerificationCert(senderPub)
                );

        ByteArrayOutputStream decryptedSecretMessage = new ByteArrayOutputStream();

        Streams.pipeAll(decryptor, decryptedSecretMessage);
        decryptor.close();

        assertArrayEquals(secretMessage, decryptedSecretMessage.toByteArray());
        OpenPgpMetadata result = decryptor.getResult();
        assertTrue(result.containsVerifiedSignatureFrom(senderPub));
        assertTrue(result.isSigned());
        assertTrue(result.isEncrypted());
        assertTrue(result.isVerified());
    }

    @ParameterizedTest
    @MethodSource("org.pgpainless.util.TestUtil#provideImplementationFactories")
    public void testDetachedSignatureCreationAndVerification(ImplementationFactory implementationFactory) throws IOException, PGPException {
        ImplementationFactory.setFactoryImplementation(implementationFactory);

        PGPSecretKeyRing signingKeys = TestKeys.getJulietSecretKeyRing();
        SecretKeyRingProtector keyRingProtector = new UnprotectedKeysProtector();
        byte[] data = testMessage.getBytes();
        ByteArrayInputStream inputStream = new ByteArrayInputStream(data);
        ByteArrayOutputStream dummyOut = new ByteArrayOutputStream();
        EncryptionStream signer = PGPainless.encryptAndOrSign().onOutputStream(dummyOut)
                .withOptions(ProducerOptions.sign(
                        new SigningOptions().addDetachedSignature(keyRingProtector, signingKeys, DocumentSignatureType.BINARY_DOCUMENT)
                ));
        Streams.pipeAll(inputStream, signer);
        signer.close();

        EncryptionResult metadata = signer.getResult();

        Set<PGPSignature> signatureSet = metadata.getDetachedSignatures().get(metadata.getDetachedSignatures().keySet().iterator().next());
        ByteArrayOutputStream sigOut = new ByteArrayOutputStream();
        ArmoredOutputStream armorOut = ArmoredOutputStreamFactory.get(sigOut);
        signatureSet.iterator().next().encode(armorOut);
        armorOut.close();
        String armorSig = sigOut.toString();

        // CHECKSTYLE:OFF
        System.out.println(armorSig);
        // CHECKSTYLE:ON

        inputStream = new ByteArrayInputStream(testMessage.getBytes());
        DecryptionStream verifier = PGPainless.decryptAndOrVerify()
                .onInputStream(inputStream)
                .withOptions(new ConsumerOptions()
                        .addVerificationOfDetachedSignatures(new ByteArrayInputStream(armorSig.getBytes()))
                        .addVerificationCert(KeyRingUtils.publicKeyRingFrom(signingKeys))
                );

        dummyOut = new ByteArrayOutputStream();
        Streams.pipeAll(verifier, dummyOut);
        verifier.close();

        OpenPgpMetadata decryptionResult = verifier.getResult();
        assertFalse(decryptionResult.getVerifiedSignatures().isEmpty());
    }

    @ParameterizedTest
    @MethodSource("org.pgpainless.util.TestUtil#provideImplementationFactories")
    public void testOnePassSignatureCreationAndVerification(ImplementationFactory implementationFactory) throws IOException, PGPException {
        ImplementationFactory.setFactoryImplementation(implementationFactory);
        PGPSecretKeyRing signingKeys = TestKeys.getJulietSecretKeyRing();
        SecretKeyRingProtector keyRingProtector = new UnprotectedKeysProtector();
        byte[] data = testMessage.getBytes();
        ByteArrayInputStream inputStream = new ByteArrayInputStream(data);
        ByteArrayOutputStream signOut = new ByteArrayOutputStream();
        EncryptionStream signer = PGPainless.encryptAndOrSign().onOutputStream(signOut)
                .withOptions(ProducerOptions.sign(
                        SigningOptions.get()
                        .addInlineSignature(keyRingProtector, signingKeys, DocumentSignatureType.BINARY_DOCUMENT)
                ).setAsciiArmor(true));
        Streams.pipeAll(inputStream, signer);
        signer.close();

        inputStream = new ByteArrayInputStream(signOut.toByteArray());
        DecryptionStream verifier = PGPainless.decryptAndOrVerify()
                .onInputStream(inputStream)
                .withOptions(new ConsumerOptions()
                        .addVerificationCert(KeyRingUtils.publicKeyRingFrom(signingKeys))
                );
        signOut = new ByteArrayOutputStream();
        Streams.pipeAll(verifier, signOut);
        verifier.close();

        OpenPgpMetadata metadata = verifier.getResult();
        assertFalse(metadata.getVerifiedSignatures().isEmpty());
    }

    @Test
    public void expiredSubkeyBacksigTest() throws IOException {
        String key = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
                "\n" +
                "xsDNBF2lnPIBDAC5cL9PQoQLTMuhjbYvb4Ncuuo0bfmgPRFywX53jPhoFf4Zg6mv\n" +
                "/seOXpgecTdOcVttfzC8ycIKrt3aQTiwOG/ctaR4Bk/t6ayNFfdUNxHWk4WCKzdz\n" +
                "/56fW2O0F23qIRd8UUJp5IIlN4RDdRCtdhVQIAuzvp2oVy/LaS2kxQoKvph/5pQ/\n" +
                "5whqsyroEWDJoSV0yOb25B/iwk/pLUFoyhDG9bj0kIzDxrEqW+7Ba8nocQlecMF3\n" +
                "X5KMN5kp2zraLv9dlBBpWW43XktjcCZgMy20SouraVma8Je/ECwUWYUiAZxLIlMv\n" +
                "9CurEOtxUw6N3RdOtLmYZS9uEnn5y1UkF88o8Nku890uk6BrewFzJyLAx5wRZ4F0\n" +
                "qV/yq36UWQ0JB/AUGhHVPdFf6pl6eaxBwT5GXvbBUibtf8YI2og5RsgTWtXfU7eb\n" +
                "SGXrl5ZMpbA6mbfhd0R8aPxWfmDWiIOhBufhMCvUHh1sApMKVZnvIff9/0Dca3wb\n" +
                "vLIwa3T4CyshfT0AEQEAAc0hQm9iIEJhYmJhZ2UgPGJvYkBvcGVucGdwLmV4YW1w\n" +
                "bGU+wsFIBBMBCgB8BYJfUbC4AgsJCRD7/MgqAV5zMEcUAAAAAAAeACBzYWx0QG5v\n" +
                "dGF0aW9ucy5zZXF1b2lhLXBncC5vcmcEc0Prq/Ohwr794nDXrgZXDdDq38GOMsus\n" +
                "hDqEwk/zJgMVCAoCmwECHgEWIQTRpm4aI7GCyZgPeIz7/MgqAV5zMAAA3rIL/3cI\n" +
                "WywtBrcW40S3lGoQL8zhl4wrI/HiXUGwEvEB/kfyfNk3uS73d5OgbOk4Xiw8QuCK\n" +
                "AX8oyAypYheb1M2Q7VW+Iohl6Jpq8QppUX7YKugnH4bYIZsdVQw5VT+69UsuHfj0\n" +
                "x6FKXw3ums2QhpB6XErd/G/npJtaK7LGoMo9ZRGKIdS+KwaXp0jU4+pgNVnzfRCA\n" +
                "4AcmRCsHI4pgoIbQ79qCdpe9KJLf+blkNZFKCUXrAegbmaQ8wG4MdH4K/hnM0HaG\n" +
                "MWiR0CKuKn8Mx4KHtTQz74jpHQAkvlqxgGulyfx+Kl6e8y4+AatJAG/62/3brIAw\n" +
                "+tFXYxnONaQm/22h84YvSp/w4DqtuqHxrkkPjjgdE4QzBuVGd6PEa/59spagX6UC\n" +
                "+UMyyVE2MadXPO1gkPmEnBcn/nOlEU3ekpysC3D2Etdxwjhso+MeWFUbQlBDdgVi\n" +
                "Sk/B/HjCPLmtH1FELnAe778L0exe+G2hLad8UHcnc2INtwFSBNUSIEYbbsYR0s7A\n" +
                "zQRdpZzyAQwA1jC/XGxjK6ddgrRfW9j+s/U00++EvIsgTs2kr3Rg0GP7FLWV0YNt\n" +
                "R1mpl55/bEl7yAxCDTkOgPUMXcaKlnQh6zrlt6H53mF6Bvs3inOHQvOsGtU0dqvb\n" +
                "1vkTF0juLiJgPlM7pWv+pNQ6IA39vKoQsTMBv4v5vYNXP9GgKbg8inUNT17BxzZY\n" +
                "Hfw5+q63ectgDm2on1e8CIRCZ76oBVwzdkVxoy3gjh1eENlk2D4P0uJNZzF1Q8GV\n" +
                "67yLANGMCDICE/OkWn6daipYDzW4iJQtYPUWP4hWhjdm+CK+hg6IQUEn2Vtvi16D\n" +
                "2blRP8BpUNNa4fNuylWVuJV76rIHvsLZ1pbM3LHpRgE8s6jivS3Rz3WRs0TmWCNn\n" +
                "vHPqWizQ3VTy+r3UQVJ5AmhJDrZdZq9iaUIuZ01PoE1+CHiJwuxPtWvVAxf2POcm\n" +
                "1M/F1fK1J0e+lKlQuyonTXqXR22Y41wrfP2aPk3nPSTW2DUAf3vRMZg57ZpRxLEh\n" +
                "EMxcM4/LMR+PABEBAAHCw0IEGAEKAnYFgl9RsLgJEPv8yCoBXnMwRxQAAAAAAB4A\n" +
                "IHNhbHRAbm90YXRpb25zLnNlcXVvaWEtcGdwLm9yZykWtbTuOtDrg4F5s48NrAHA\n" +
                "kwkoLb8ZgAbb9VV8JPKRApsCwUKgBBkBCgB1BYJfUbC4BYMAeEzgCRB8L6pN+Tw3\n" +
                "skcUAAAAAAAeACBzYWx0QG5vdGF0aW9ucy5zZXF1b2lhLXBncC5vcmemJbX0gOh6\n" +
                "Z+WJo5dyEuNnG7CDklyLHJ8BY2QKoO88ehYhBB3c4V8JIXzuLzs3YHwvqk35PDey\n" +
                "AAAPrwv+OSxllLwrRUB0BqRYS2/D1qFHFOn0qBOMJaL0X2yjint67SeHosxmvqSg\n" +
                "5tnQmaHljFrMZkf6PSGYdz0VwalT8XaubcGyljSxrgc7Qs5jdxKL5IhTfjEb0Q4v\n" +
                "8TSp3esG02ZafGAZSwIIW1RfUEMk+XHciEk2pRDkraCAlcCvqL2En+eNLCqWzpTI\n" +
                "Fcp0lb2JxRlozzqpfVNq++UXaHaqrGflbrTn4x+1i6zuxCVkjt4gHjQRLACDmEFk\n" +
                "mSZxqYZmQdvEfkdSg2XgTjg+QhHunpQyCbxrW5R4qYgm7yjctgv9keVDbIy2lRIM\n" +
                "kNWZhZWijw1SxPGVWlKVizi+pWZyX9NBrTAj/ES/HZrLda52PR1BKSE4kG74T/73\n" +
                "V/jnqYp0jGI/M3y79DRq2tlO5p6Jp+OcmU2SyvItaNhoateGndLIVPZfAT69avbY\n" +
                "tMoEbsA/biVL4xN9SqaLian4ow9/pVm/z4Ej6zSRZUC01hZBQWD02z0ntU7t0CPR\n" +
                "R58XC9znFiEE0aZuGiOxgsmYD3iM+/zIKgFeczAAAED5C/975SfSeub9RJHilYFA\n" +
                "eeeHU6ZaSpOy0/ZrwSUFmvDrxowiCNn7sYZEZmIBVZ/nIlfbCUUTesIF92aLkIZe\n" +
                "EMQUiXP0/HtnAx1duQ8htdb+X/EhuWPPJ7hF5bA6AB1oXVKn3lpggHzauGSilI5m\n" +
                "dPXXVdDUWuDQfSn459UOv4PwB52uLtGZK3iprVgYD3RzSWktHMhMvcB2GXNQlfyo\n" +
                "yWewq9p+wwbIFUFZYMRIGjJNSc6aQcEHusIn85E+Uid/hrDIiblbvQA+7ONcoaqL\n" +
                "DiLSL+bh1/usrmzccUK01nLMmTnG03vU3WR3yqmDlzgU/S3XfZRPECwr6AzNSXoe\n" +
                "d4u9/SPt2VBxGtZ0yA4PXgO6PbZC6EIZqmgW5oKjSWZwkryQLGKji+vYJU1FzM+3\n" +
                "qO6PYqLVGf97n6LS2xD10rrJ2aUq0CQ/M5ykRVsT6HifV9wPiPzR8ilcXWRT8CQ2\n" +
                "Ks2WqI282/DM+Lq/GCSd2nXtS3/KwErTFiF1uHi/N3TwdWA=\n" +
                "=j1TE\n" +
                "-----END PGP PUBLIC KEY BLOCK-----\n";

        PGPPublicKeyRing publicKeys = PGPainless.readKeyRing().publicKeyRing(key);

        assertThrows(IllegalArgumentException.class, () ->
                EncryptionOptions.encryptCommunications()
                        .addRecipient(publicKeys));
    }
}
