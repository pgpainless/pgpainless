// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.policy;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.util.io.Streams;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.DocumentSignatureType;
import org.pgpainless.decryption_verification.ConsumerOptions;
import org.pgpainless.decryption_verification.DecryptionStream;
import org.pgpainless.decryption_verification.MessageMetadata;
import org.pgpainless.encryption_signing.EncryptionOptions;
import org.pgpainless.encryption_signing.EncryptionStream;
import org.pgpainless.encryption_signing.ProducerOptions;
import org.pgpainless.encryption_signing.SigningOptions;
import org.pgpainless.exception.KeyException;
import org.pgpainless.key.generation.type.rsa.RsaLength;
import org.pgpainless.key.protection.SecretKeyRingProtector;
import org.pgpainless.util.Passphrase;

public class WeakRSAKeyTest {

    /**
     * Test key.
     * RSA-4096 CERTIFY_OTHERS
     * - RSA-1024 SIGN_DATA
     * - RSA-1024 ENCRYPT_COMMS, ENCRYPT_STORAGE
     */
    private static final String WEAK_RSA_KEY = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
            "Version: PGPainless\n" +
            "Comment: 88FB 13F4 2DA6 8480 573D  200B 90DC 9A01 1496 8242\n" +
            "Comment: Alice <alice@pgpainless.org>\n" +
            "\n" +
            "lQcYBGSHDHcBEACKzJaLOQAG36oZPUJmes0YmbLe8oZt33hIaRLxj7mI4oOqOlMp\n" +
            "nyYKhg4KmneFwXkYLe9/LlT194ZDVQi1qYR91DUNsM9sTWNIVEq8Bk88Rc8zSg8r\n" +
            "R6QcADNf+P9cz/NlR8pcet89CP84WrytEFQe942APKSvkOejOSdJZRYo6aV25N/0\n" +
            "Oh3m16T09JHEBc6SkkutjJ9sp7x/bHSqRZrUIyFJsf3zL3o3u+cQ0sO0h2nIt4zW\n" +
            "Z7q58UNka1+CUy0FRaYMtjLOou3OEI2YmewMPzeam9qpCMn31fxZRA8VEDJFFjYq\n" +
            "8KbjsdxeTVMvPwbMaKQrAd6ekLQpbRVc5SEQngySDL3fkZoOksyZlb02TDk2/yiG\n" +
            "VkATMvJEf0WQ2PXCJoS1sJ++rSIHK/ZwAfofU4ScZcoZ2A+KAm6cGmCOsTuARKsS\n" +
            "aon0JIxAEIbTWWon1bZjwdWreGRpIotBabOVmJI02VPAtoCwBUrQSraROmbaZiwh\n" +
            "Veitcbsnw8kksnQW2WU6isxe9+wcz4zoy4I0/7LO9PYfF0QX1HidhuY6dh0OoDPs\n" +
            "wXf9jnefSbOhDsB2e8DnAd1TBkQi2CbNDneCgwkqUefue4kAOQAdkKSurruiWVfR\n" +
            "pUx6h1zGiZd9Xx9KBqW8lcGFuQkmNBf2wPAaGOoHWNYK+3Cjg9/JjYV/aQARAQAB\n" +
            "AA/9HRuqtqfNiaN+WKywMC2wtWgGSxsxdflXkFf40RADKOHYGusAZcoqgCp851xd\n" +
            "lH9uldOMVm+xAaRXU+eRXAeg8YJ/Xc+msF/KYnDK+4OXOlyph2gQplLv569jFs1x\n" +
            "QFWcBbF4jsx15KbuXzMoPmMeQSBJXItbPjZ1XZWu14WLkCjvum9lSCKoArFWtshT\n" +
            "iXhuSe7EUDEdffvvXAmyrcLLJZH4eSwKxeU/DFErtCt/P2zmkmFr98rpLfWa3IRo\n" +
            "Ezy+REzG9gN/xDYHCSAPkeE1z5uyXYox4SEmugL2WQIc553t7O8rjPXLChVS0bQF\n" +
            "rfLZyiRnyV0rArX2Enn98O1ccYCi/7zh3UDfWVp4QeYCajxLMusCgwY7CNAarnrG\n" +
            "5ue7D5rI4PLzmWx2q/HI++GANEIyUFoDwZ8GH49WnYZJx3m1CuDy2H8NaALOXamm\n" +
            "uVN3ZQekrIDLA9SodfXt9yxvRb48Gi6VDvgVEezcgY4HT9wEkLBjqFxEcu+owKso\n" +
            "7Sr2Q3oYij+aIL+QWUD3WGyCUhOlurWu0nvlMsGrm2CYq3Scnf4wlz/bSSQ5USwO\n" +
            "clyaNck41I34BqULljbQn651LV2a++M74DeZapy0RgT1ShYYaBA6oQ/OVuIrPEHJ\n" +
            "rZgUlt/tBtL6xyDKI43/VGQzb6/J6byDsCWIpgRnUVICbsEIALs2aXjrau3wMb95\n" +
            "gK5qjNRNnaLDRNjkb1Vf8jJOsT2s5/J3K6uOEO1XB26BFQzQbQ+JrqKKD3NfuRY2\n" +
            "g2pk+IiU46r3/xEOQMKO9MS5AlAN5y7y34OtPAj7uchrbUShrDy26UvOBIaZddNq\n" +
            "gSGn8lsQCE0CFGX/4ke48TsK9GSocYfdgEECAPzcUdu1ws8PnxhfNLoBRBl/PD/W\n" +
            "gfIsNNuMJyA7KixjgT6DKSjFRHPVxSa990ewqtCa10Eqwn5DGM10bDymKQIpkj1j\n" +
            "0bbNNT7sP7ZPrinD05h2sr2AfzIxAgeB6BCd4m761BBpUB+hDVtl+kgDIc+kQp+P\n" +
            "8ib4AFsIAL3MURxJLVx/8v6B9EeA2cWaQQf0V62sa+2ZgBgdSW3y4ryvvfP/RNg6\n" +
            "majNnOxLkD8W5TA/0ujdJERRfJUGW2I71bV1NZYrZsmU+mIS5uZ6fg/IzcCNFIt9\n" +
            "8dc4UgOSUWogk8XczYaNViw+Nx9a9AtdI/Y3AB+m8iDZrRLYjrRAM3fARU/3qObG\n" +
            "nQhkiI8r+x6c8jtf/aj86SlgTNM8VKFFKJCv8RC2JLQLTvzgrqczETscAvjSkZ1U\n" +
            "vuEQe9QQIdWcnLzl6ql5BKreG7KXHqBXUTDW8OwyZkDQpi5TgK0KBEMEHTywtiWs\n" +
            "fTNschzXeJBV+nf8sinYriJZkcm5SosH/0ojJRXc/yW2UZt01IE48tze2rPGYzyl\n" +
            "JH5dtNkh5nRtUaycdi35rjYYxL23wcZ33epxV6tWs2lTcLc4b4GS9sCR5zl+98V7\n" +
            "iu/+CXVOMz9Eo6LXBHr/QX6Pgkwct4ygDYdexcHMMJnn7HbprVvmTEiKHBVb823r\n" +
            "nXbu2myeNea8yVoQDk9uiOjdp7SB2lr4QZ6ai9jC1WZsJ1JYBV3ndssJ3taMRpKX\n" +
            "Kv3gwgR+MxLOdde1Bf+6RGCOW9ZrAqZvBycXXxppsUwg8rxl4LPd61Mb7QLpsqZg\n" +
            "m3XkCI+NbL4YsHyr4cQBnJg7qRFWBvO+yDwav3ymM5ZGTrxnbrqfF/6D6rQcQWxp\n" +
            "Y2UgPGFsaWNlQHBncGFpbmxlc3Mub3JnPokCUwQTAQoARwUCZIcMdwkQkNyaARSW\n" +
            "gkIWIQSI+xP0LaaEgFc9IAuQ3JoBFJaCQgKeAQKbAQUWAgMBAAQLCQgHBRUKCQgL\n" +
            "BYkJZgF/ApkBAAChRg//VVpi93b0gwsuzqTxjHF9C8KyWW5POV8JGRedtUs6qXly\n" +
            "Q6hy2ZiBkMJWJnZByKjJXhayLeHAVQXQtY+8Cy5YbdzzqbQ9I7puQvw1Kf+DQKnr\n" +
            "FbxzxaPMdAnQgAfaS+0WhXLBz3OYonUCCiqRAQlWb0rGJz4H8hsGQRATVjCgSGnU\n" +
            "cE7rOiJ4JzqyOHQZY+EbZ89rngE7whn2T4j/9728girM6Zy519dyZKe3Gma9/IPj\n" +
            "WAs+94m5dw3EzaJcyWbxB333Gg1CSsFaa3j30TuxmdxuWzkJ4SI6L8j9ppeMYPeF\n" +
            "a/NW3VveUO6PqXEOThcxwOWvQp0lz5FoT7o+9VQ1lbKJGbpwtYgJ9IySx2/P64pF\n" +
            "scUXXERz8Cfh5WwnpzHVUp/NHEuVqjU5dRlhXwgL66KiRrnbxBquifRtu0rgyVop\n" +
            "SgCkapAinvBcnLIjIiKJn9KpSzvzh1psyAr95mCCzRKhJfgA93+fGYIHl1xi2tsO\n" +
            "WsjU7MQcH+ZftRZdCmgmnxpn7z5TCVqM4zMezAEwRv0AmW0SdTTGri6fA/EKOQPS\n" +
            "9Uf2yRr9gveh0Xr1ohHVloyh7fXt6rNX9SuOSZ8NLETELj9mcligVH+iPOUhobiy\n" +
            "MSh+EE346g9HRXRm/16tARQFGuaGu7+w+IrBoRJKM9Kghfc5gDyy7tQox2QyP3ad\n" +
            "AdgEZIcMdwEEAMuBMOMAhNBgya5lS9dRV4+mOWZF6GG8VG/Kgl0slTrm+rOJeZPR\n" +
            "QHDEJB5JXUM57UklX4Uf0IupZkcnfuf0vm5KERMg6l3XnXg6DIBiQze3QnpJJSWz\n" +
            "9aMCx+TkG9R0A2htSe2y55XvaEMxOKUa8vJjk8SKX2mlEONd8xPBZ2k9ABEBAAEA\n" +
            "A/0S5SLp4NF0G5h+Rc995YKQxulLcrA56ueYHaBvEEWm221poBkWvXYTQlLsMPmk\n" +
            "1UsP4JV24dZWMVtavfMNjG7l2irWKJq7YmpkjJypJ+BYPGUfM0MISt/blZhxZRRm\n" +
            "xSUsADd8VXfARRdxLoDE2vNSXkX+y5PDffOHho6llSx1DQIA1xZPteS2rFL/0FO/\n" +
            "MaNyjErpYVomg1M6LMON3XQDR6YYndum4uQNgj7IqSbE8iJDU9uGWRC44EQZoSUS\n" +
            "NY90BwIA8jbeXeaQMTtz3oBDdc8t2cFwKIepE0NEuGXm+Eaj4dwbSiwpEg+pCa1R\n" +
            "DVoNxp1i43IxQLlLbrjz44Ch19JPmwH/WHTni5h/8kszv/Ra9G6irjq2SQtnZ5m9\n" +
            "b2h2snUizKebCmTQ0wZlfLpGHGFnWgpkf882QZ/rPzr8jk/TKQ4F4J6NiQLRBBgB\n" +
            "CgC7BQJkhwx3Ap4BApsCBRYCAwEABAsJCAcFFQoJCAudIAQZAQoABgUCZIcMdwAK\n" +
            "CRAdzMPWl9+PZqgmA/938qa58LMuj+17YYj7QKeJ+YojJsDiwm0kpAqcUKvODQw+\n" +
            "65EpTjrktyX/jhya09Ag9mBQklFJfIGA9C4eWHBfVIwulYFyPyBtHtFMJXLacXoW\n" +
            "h3d7eYsay62nHQKEiiwCULnL/yoQc1gapSYu7/7J6kBk+1y1KJUG867PWq3QtgAK\n" +
            "CRCQ3JoBFJaCQtsWD/kBE2w/EZrvPBEl96POfQwOJL3zsozZ+QEEvPKOAsXfoaMK\n" +
            "Ff3i1HF3ts/NYHfeT0kHEsVMcODEfQv5LbbcF6BLeusDkuNEg1N8l/LwjN9UnrQW\n" +
            "biQjpEHafETcocvr9XwVYKx4+rGQ3SGvqxb6iiVKHGBprFbeqhQdASRTP9zYMI/4\n" +
            "eZnXADrfGGJt2P7AaDzcKCSOH/E9KQYROoDFsHYhyX/DFZZsMX8lNRfTDjfsu49+\n" +
            "J+xcSUrFKYYpa3DPS5O+Q9glBFPeeLq7LiqE5c7XwrJtJUcurxMswcv7y3b1fQW2\n" +
            "+fR3ucmT/3C6n8SSXbPBxoRaK1xBwwXbjSrhVjl8/yrjZmxnQEpIbe5eFvy1WAHH\n" +
            "vdUfRDlD/IRczmkSfeTet3YAWqs5uSNwc+wo0zpPzyrHSWdB/5SXfgo/pPugdhSp\n" +
            "LDFM1SSHtthgiMVxcZD0yE5YK81PMI9SXRcG608opGPCLnIiYoN21rbuF/z6tITk\n" +
            "SVKLbbOJ/M3lV0elIBWLUl7UPNL0Ss+yvLpezwx7Bx/GCEsA7N5RMy9q1wSKhUmb\n" +
            "mT0SdVwM1BztRXESIxilA61uob8wUPxtPFBlMH0tSUtfnInWi45y3W0YmGQsLNYQ\n" +
            "Sr99oL5LLHFVUbkP8boo6O65YkKGV0tDbW6J6Nk7NOquCFjuhNH1UffnEPSD4Z0B\n" +
            "2ARkhwx3AQQAizGy1gpu9cK2iPefbK5U+/0WvQNf+VMt/k0cr7vd2SP6pAaPHWoC\n" +
            "QDigYcv3DsvIWSLvMUAcVKZ7kysf8kPfrceoPqJjw8B5kxV80QYJ9V9efXpJ2ALb\n" +
            "kmggXoKyW8cink6TS2HkeF2q4pwgrG6Jcc5TlNIPMYVuu0qnPuFTRNkAEQEAAQAD\n" +
            "/R3pMRfjqBJxpA3swDp3f9WifjdhuUb3g+OoqGhvA2482AhVTH2yoQcx4+0ACngI\n" +
            "fGYDJsk7kJr0J4vpcXT69t6s3gH/uOO+MFHQa6u6qRejKcNOW8qnENDB9PN81Nu3\n" +
            "wbiNn5+BnjPSl9H6rL6Lqh5qk9X57gR2l6ty8EtZHntxAgC1U9rFbopj9AGhAMdr\n" +
            "qc5koUUjvyrXAsZlqCeyxRipf1M3UEMCgETa8DWcFGZkotYJCf7kNXqeRS/9nkpP\n" +
            "9PB9AgDEhAAk0T3QRxvUi9Aw6RApVxHVv8rNzcjHMlR7idrtQiUObJXK61P67aLn\n" +
            "BZ3QApneE9wZqM8DlxVsj2mSXxCNAgCi6FJY/uSHYA8NL2KDzKrdGtW3YdLcr8Ud\n" +
            "LUAR3YTLTzFXUPaxQ1nkPcSkVVd/6LQ10VmwioTvMQP/Vs+gcB36p0eJAjMEGAEK\n" +
            "AB0FAmSHDHcCngECmwwFFgIDAQAECwkIBwUVCgkICwAKCRCQ3JoBFJaCQj+lD/42\n" +
            "iRWNTDKg+gBhz1ZBrt2VR8C4Rm8g1HyJ1SWeftLI5PmgfqVQUYG2JfCwaAyBQrrd\n" +
            "UExxdYeEv9hjYDDPRl/ZFMzKLGZxxPs0s7I32tiMYrMrJYxDqc/cmO1siFWisgT9\n" +
            "KkDs8vZbLTVEPy0cD/xg2M6N/atHD90HqPmi+qwuote328zR5piX7GThtVwJnYGN\n" +
            "rfqRWsunHk+dvw4g2gjw9hwHafzqJ2APhWLi3wmIUAVjbJLl25Zkaxnm2zkj85sp\n" +
            "Z1Ly9cjJlmlV9/N+762lwtvEGno7Umi5NdXtwqQVN6vHVQEvS5cypwcfO9FnLXh0\n" +
            "n+XqaEtp5EEQJOqEjsw1a/l3HpqteexsjXoGdPKmDY4xqMDduYXcklgg9vfTdbGb\n" +
            "CslbUFLmJjzMBeukhS/51r39FmmBpQF9zC7U//hKMQy6rsI/gSnPMT3c7oMNZAbo\n" +
            "q+9HSfMtt6SriQBg9TUn+QnrQotJKpXh1gX/rqkAz7azmlNcvSI5TTcBM74LcsWg\n" +
            "ntlUcNI96UYFyiiBzYjESdCinQFlBwSKKtSvLUFrrANmmkTZHFCrE1Ig/w6vDXoN\n" +
            "rsFTjG7e6Mz/uEeSA3e0n/xk7/6WPQDCYP/3qRGErAgPNK5zVavHI0Bzw+A/DP7s\n" +
            "fr7HL/cch3YQK5AKifvyATqF72k7BjrFETP6Ly4X3A==\n" +
            "=nxQa\n" +
            "-----END PGP PRIVATE KEY BLOCK-----";

    @Test
    public void cannotGenerateWeakKeyWithDefaultPolicyTest() {
        String userId = "Alice <alice@pgpainless.org>";
        assertThrows(IllegalArgumentException.class, () ->
                PGPainless.generateKeyRing()
                        .rsaKeyRing(userId, RsaLength._1024, Passphrase.emptyPassphrase()));
    }

    @Test
    public void cannotSignWithWeakKey() throws IOException {
        PGPSecretKeyRing secretKeys = PGPainless.readKeyRing().secretKeyRing(WEAK_RSA_KEY);
        SecretKeyRingProtector protector = SecretKeyRingProtector.unprotectedKeys();

        SigningOptions signingOptions = SigningOptions.get();

        assertThrows(KeyException.UnacceptableSigningKeyException.class,
                () -> signingOptions.addInlineSignature(
                        protector, secretKeys, DocumentSignatureType.CANONICAL_TEXT_DOCUMENT));
    }

    @Test
    public void encryptDecryptRoundTripWithWeakRSAKey() throws IOException, PGPException {
        PGPSecretKeyRing secretKeys = PGPainless.readKeyRing().secretKeyRing(WEAK_RSA_KEY);
        PGPPublicKeyRing publicKeys = PGPainless.extractCertificate(secretKeys);

        ByteArrayOutputStream encryptOut = new ByteArrayOutputStream();
        EncryptionOptions encryptionOptions = EncryptionOptions.encryptCommunications()
                .addRecipient(publicKeys);

        EncryptionStream encryptionStream = PGPainless.encryptAndOrSign()
                .onOutputStream(encryptOut)
                .withOptions(ProducerOptions.encrypt(encryptionOptions));

        encryptionStream.write("Hello, World!\n".getBytes(StandardCharsets.UTF_8));
        encryptionStream.close();

        ByteArrayInputStream ciphertextIn = new ByteArrayInputStream(encryptOut.toByteArray());
        ByteArrayOutputStream plaintextOut = new ByteArrayOutputStream();
        DecryptionStream decryptionStream = PGPainless.decryptAndOrVerify()
                .onInputStream(ciphertextIn)
                .withOptions(ConsumerOptions.get()
                        .addDecryptionKey(secretKeys));
        Streams.pipeAll(decryptionStream, plaintextOut);
        decryptionStream.close();

        MessageMetadata metadata = decryptionStream.getMetadata();
        assertTrue(metadata.isEncryptedFor(secretKeys));
    }
}
