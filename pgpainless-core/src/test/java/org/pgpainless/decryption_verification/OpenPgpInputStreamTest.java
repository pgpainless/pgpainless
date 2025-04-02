// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.decryption_verification;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Random;

import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.bcpg.CompressionAlgorithmTags;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.api.OpenPGPKey;
import org.bouncycastle.util.io.Streams;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.CompressionAlgorithm;
import org.pgpainless.encryption_signing.EncryptionStream;
import org.pgpainless.encryption_signing.ProducerOptions;
import org.pgpainless.encryption_signing.SigningOptions;
import org.pgpainless.key.protection.SecretKeyRingProtector;

public class OpenPgpInputStreamTest {

    private static final Random RANDOM = new Random();

    @Test
    public void randomBytesDoNotContainOpenPgpData() throws IOException {
        byte[] randomBytes = new byte[1000000];
        RANDOM.nextBytes(randomBytes);
        ByteArrayInputStream randomIn = new ByteArrayInputStream(randomBytes);

        OpenPgpInputStream openPgpInputStream = new OpenPgpInputStream(randomIn);
        assertFalse(openPgpInputStream.isAsciiArmored());
        assertFalse(openPgpInputStream.isLikelyOpenPgpMessage());

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        Streams.pipeAll(openPgpInputStream, out);
        byte[] outBytes = out.toByteArray();

        assertArrayEquals(randomBytes, outBytes);
    }

    @Test
    public void largeCompressedDataIsBinaryOpenPgp() throws IOException {
        // Since we are compressing RANDOM data, the output will likely be roughly the same size
        // So we very likely will end up with data larger than the MAX_BUFFER_SIZE
        byte[] randomBytes = new byte[OpenPgpInputStream.MAX_BUFFER_SIZE * 10];
        RANDOM.nextBytes(randomBytes);

        ByteArrayOutputStream compressedDataPacket = new ByteArrayOutputStream();
        PGPCompressedDataGenerator compressedDataGenerator = new PGPCompressedDataGenerator(CompressionAlgorithmTags.ZIP);
        OutputStream compressor = compressedDataGenerator.open(compressedDataPacket);
        compressor.write(randomBytes);
        compressor.close();

        OpenPgpInputStream inputStream = new OpenPgpInputStream(new ByteArrayInputStream(compressedDataPacket.toByteArray()));
        assertFalse(inputStream.isAsciiArmored());
        assertFalse(inputStream.isNonOpenPgp());
        assertTrue(inputStream.isBinaryOpenPgp());
        assertTrue(inputStream.isLikelyOpenPgpMessage());
    }

    @Test
    public void shortAsciiArmoredMessageIsAsciiArmored() throws IOException {
        String asciiArmoredMessage = "-----BEGIN PGP MESSAGE-----\n" +
                "\n" +
                "wcDMAwAAAAAAAAAAAQv9FBhYmbkqLBVrhUUPouXTiXJ/ElyDknSW0xTDgofFbIZ5\n" +
                "9ABYrYHaDEUAupwYzh5H8xNiL70/RdI0cMv7k2Rqlug/W4f0Mz+wYJ4xN24NzRQ5\n" +
                "BqlsTIlXwJI0N4Rj7KSBfVhSHYEm0EtA4qx8ylL3vJfAH1AH7bBLjSzkDYE7dvu8\n" +
                "2/PigN2c0tQ+AG4O+QV8zgJpc0tE2bh0h1eiXarhOZZSNjJKqmYZ4PlhgdiQBRs7\n" +
                "a7EgkdNYMUTCbBiEpyQiiorDIxqmiaQVJjoCmSiSMCxvae9ozue6x1FvFyZWEPdV\n" +
                "Lp8pSnuZwQt7jAw/Qm3u1ogyNdQaoXF/pDuwJEf0ufYwMsI7wDUVUJiRL23BGDOB\n" +
                "h2YbFu7TWz63wkwjTs8bfeQ8JPmWXTG75Z95sjaiMloGhKwhYem8XPWAmh6xLWfF\n" +
                "TgYU/AgKTgBvb/WugSLpi1zSOjkET3IY00vjvCzfwxxojJd/vfaSdOQX2EbADwgm\n" +
                "KAmdO0Q9+BRuBDNPAEH/0j8BuiicOrrHRd0c9T4ku9u1vvxGJCMwiKPj9TGlxxpw\n" +
                "C5uUVzvOSzGKfZ5ZH4SToaMhbYW37UXtA7URW1zF86c=\n" +
                "=Yz3x\n" +
                "-----END PGP MESSAGE-----";

        ByteArrayInputStream asciiIn = new ByteArrayInputStream(asciiArmoredMessage.getBytes(StandardCharsets.UTF_8));
        OpenPgpInputStream openPgpInputStream = new OpenPgpInputStream(asciiIn);

        assertTrue(openPgpInputStream.isAsciiArmored());
        assertFalse(openPgpInputStream.isNonOpenPgp());
        assertFalse(openPgpInputStream.isBinaryOpenPgp());

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        Streams.pipeAll(openPgpInputStream, out);

        assertArrayEquals(asciiArmoredMessage.getBytes(StandardCharsets.UTF_8), out.toByteArray());
    }

    String longAsciiArmoredMessage = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
            "Comment: 7F91 16FE A90A 5983 936C  7CFA A027 DB2F 3E1E 118A\n" +
            "Comment: Paul Schaub <vanitasvitae@fsfe.org>\n" +
            "Comment: Paul Schaub <vanitasvitae@mailbox.org>\n" +
            "Comment: Paul Schaub <vanitasvitae@riseup.net>\n" +
            "\n" +
            "xsFNBFfz1ucBEADXSvUjnOWSzgW5hXki1xUpGv7vacT8XqqGbO9Z32P3eFxa4E9J\n" +
            "vveJmx+voxRWpleZ/L6XCYYmCKnagjF0fMxFD1Zxicp5tzbruC1cm/Els0IJVjFV\n" +
            "RLke3SegTHxHncA8+BYn2k/VnTKwDXzP0ZLyc7mUbDl8CCtWGGUkXpaa7WyZIA/q\n" +
            "mvUqh7671Vr4vJlq0kFbUibsFblZjk9uydHvvqaVpmBzbr/gWDyirHXwPl5lCnWp\n" +
            "ORjT7tc8hjyt+dxpmnGdqlDIcqUjdCWoN6NxffLtKz/XpJ+dBvA8rXT/QaPSaVCG\n" +
            "o0DbgybvRF1HvX30udx4FF9fFsVAbYP1mvZx4fHy+Z1rJJhODZv1YpH7YY1bmG02\n" +
            "vfFkwpW4AyAdsONA+n/XdMCsA006/pljNd3GxjcqB5D6BhpdUvcgUslkuELsVYWb\n" +
            "EyhxKzzJvZNjQ/iHsaThooy9SFHc71PgYdyEL/WzoGr421GwpCL6BuE0rlumgaTm\n" +
            "joU/9ydLO6zpbV4RYDgtsaGQxOxVc0y1Lj8CWTi/XYIVRnmqrjGmubRV7q8pTxrg\n" +
            "oyk2zwQ+twyxp/8ZRHzl5ISiDLKSDlcMK1oa7NqyL+MCwiswpaObk56HxgF2ZwEb\n" +
            "JZYCwetxyTK7HX4/WV0V6TaPzS7dHAsb6t1Aq8IS1JdGjWKRPkjkhR95nQARAQAB\n" +
            "zSNQYXVsIFNjaGF1YiA8dmFuaXRhc3ZpdGFlQGZzZmUub3JnPsLEAgQTAQoCrAIb\n" +
            "AwYLCQgHAwIGFQgCCQoLBBYCAwECHgECF4ACGQEWIQR/kRb+qQpZg5NsfPqgJ9sv\n" +
            "Ph4RigUCYAwbLDUUgAAAAAASABpwcm9vZkBtZXRhY29kZS5iaXpkbnM6amFiYmVy\n" +
            "aGVhZC50az90eXBlPVRYVD4UgAAAAAASACNwcm9vZkBtZXRhY29kZS5iaXpodHRw\n" +
            "czovL2Zvc3N0b2Rvbi5vcmcvQHZhbml0YXN2aXRhZZAUgAAAAAASAHVwcm9vZkBt\n" +
            "ZXRhY29kZS5iaXp4bXBwOnZhbml0YXN2aXRhZUBqYWJiZXJoZWFkLnRrP29tZW1v\n" +
            "LXNpZC0yMDkzNjgxNTQ1PTYyODlhYTNiZDhhNTAxYTM2MzIyYTBmODk0ZjhkMWQ5\n" +
            "NzE4ZGVkMDM2MTYwMzlmMWNmNDhiMmE0MWVlMzU5MjCPFIAAAAAAEgB0cHJvb2ZA\n" +
            "bWV0YWNvZGUuYml6eG1wcDp2YW5pdGFzdml0YWVAamFiYmVyaGVhZC50az9vbWVt\n" +
            "by1zaWQtMTk5MTQxODIwPWY0YThmZjg0MDA0MzkzYTg3ZjcwMTNjNjAwNjViZGM4\n" +
            "OWIxMTY5ZWJjZmI4MDYwYzRmOTY2OWI0M2JhMGM4MTSQFIAAAAAAEgB1cHJvb2ZA\n" +
            "bWV0YWNvZGUuYml6eG1wcDp2YW5pdGFzdml0YWVAamFiYmVyaGVhZC50az9vbWVt\n" +
            "by1zaWQtMTQyOTY3NzEyNT1lOGE3YjEyMzZiODUwYjQ2N2E1MDkyYzBiZGZlYTg2\n" +
            "YTUzZTM2ODQyODNhMWQ1ZmUyNmVmNTg3MmRkMGFlZjQxSBSAAAAAABIALXByb29m\n" +
            "QG1ldGFjb2RlLmJpemh0dHBzOi8vY29kZWJlcmcub3JnL3Zhbml0YXN2aXRhZS9n\n" +
            "aXRlYV9wcm9vZgAKCRCgJ9svPh4RivdTEADC3xMcrcDR/+4JlDl5fblecfJHr3/E\n" +
            "0fzkPWJJBL+TIn3ON2sSKIfLn9M7NYWIGT0QLI4LnqT+SZ3Ont1h8irM4O8LuTwZ\n" +
            "kqjLkytGhgCErSdGzJ3oIcdXcnzX/p6fmxer1Qg/bpFy8mRrpSQ5tI0TYUXfD0qs\n" +
            "BEbUhB3Tsg8AYaDRcdPx8gf1METZDxx/E6RQNzVIfyCK8hszzU1pRFr15DYDCjl5\n" +
            "RZjTxXqxJFKUz85LvQToaFo5SXgH/fWf0EeoD+YNqyhROYr8iWMLCLiHqvqkEXny\n" +
            "lm7qNlFxFGFSu8Mcj6HSet5qvRj2wn6XssOWm2pOalDJx+L/biETr5vEnBwfw7p2\n" +
            "1Pmrg/jhK9yasKsdYKRlJdJWOtpEi9amcQ4sGA9OD74weJ/zEEPgLKbvkWFuUy8a\n" +
            "69AEeKAbB3RH3r7+PRnPVvxC3MpEmLsRsjVdP21xGhtnqAzJFkMRXf5lpC6czJiH\n" +
            "gd/sao0mJPrkWUHDn0k9rgoZI9gRRENk3tXefjwQ2A5aEcAagmb2l0DjugYAb7dU\n" +
            "ip9bJNUhBgjiaWYBj9uZOzYdQ7kFcFWp7iCGvkoeBMQf29rXZOZsxQmKLgEPZuCl\n" +
            "YmIO4PS6sERoPT+FUGl85YAkEIBII0TCQdVQd/Vx6JRLc/f/cFCoKBv2+9LKVPIp\n" +
            "wNNL5J+0m/H1dMLDzAQTAQoCdgIbAwYLCQgHAwIGFQgCCQoLBBYCAwECHgECF4AC\n" +
            "GQEWIQR/kRb+qQpZg5NsfPqgJ9svPh4RigUCX8gjtUgUgAAAAAASAC1wcm9vZkBt\n" +
            "ZXRhY29kZS5iaXpodHRwczovL2NvZGViZXJnLm9yZy92YW5pdGFzdml0YWUvZ2l0\n" +
            "ZWFfcHJvb2aQFIAAAAAAEgB1cHJvb2ZAbWV0YWNvZGUuYml6eG1wcDp2YW5pdGFz\n" +
            "dml0YWVAamFiYmVyaGVhZC50az9vbWVtby1zaWQtMTQyOTY3NzEyNT1lOGE3YjEy\n" +
            "MzZiODUwYjQ2N2E1MDkyYzBiZGZlYTg2YTUzZTM2ODQyODNhMWQ1ZmUyNmVmNTg3\n" +
            "MmRkMGFlZjQxjxSAAAAAABIAdHByb29mQG1ldGFjb2RlLmJpenhtcHA6dmFuaXRh\n" +
            "c3ZpdGFlQGphYmJlcmhlYWQudGs/b21lbW8tc2lkLTE5OTE0MTgyMD1mNGE4ZmY4\n" +
            "NDAwNDM5M2E4N2Y3MDEzYzYwMDY1YmRjODliMTE2OWViY2ZiODA2MGM0Zjk2Njli\n" +
            "NDNiYTBjODE0kBSAAAAAABIAdXByb29mQG1ldGFjb2RlLmJpenhtcHA6dmFuaXRh\n" +
            "c3ZpdGFlQGphYmJlcmhlYWQudGs/b21lbW8tc2lkLTIwOTM2ODE1NDU9NjI4OWFh\n" +
            "M2JkOGE1MDFhMzYzMjJhMGY4OTRmOGQxZDk3MThkZWQwMzYxNjAzOWYxY2Y0OGIy\n" +
            "YTQxZWUzNTkyMD4UgAAAAAASACNwcm9vZkBtZXRhY29kZS5iaXpodHRwczovL2Zv\n" +
            "c3N0b2Rvbi5vcmcvQHZhbml0YXN2aXRhZQAKCRCgJ9svPh4RiiRwD/47o9xzTDXB\n" +
            "thNwd/T1UWKSNtLoPX6V4V2hUW/z1SZulba9i041fM04yaauqOFrKfoFJjovdZis\n" +
            "UZeYs0Bfjf87JoJwN6TgX/7bQjSncBKHmKDXI7SLuY9dtYvqGCUOlVPTr4lxm1Ht\n" +
            "CK5XJWzMjE/mUaPwUeP8agG2lRko46K2O4msUGvnZt/m6ggtyn7WhdxHAMEiBxmk\n" +
            "j0lTIj5Q78hMxlWCI7D9bSNkRSHKN+5AQ0OIQCQnvbh1Gz85DO+VJdtr529L5pz+\n" +
            "WEsrApGbjhi3UYfIS5fBTMfIcOZ8gs7fty79LOBuweAKKWnLt6jrRlBZ16D8LuM+\n" +
            "1nrPUzTIanuqFLiysBhKBrX16UCKsW+kRvWLRG4AnEdWVlJr79kSzbzVYPHwKBqb\n" +
            "41fagZdQdxt0xZcA2wGdV7UKLbY+rNew4PC9Lt+nS6pnItT0hlSVdPOBKoieoLR0\n" +
            "XQAPM+Cr1qGlCFWNbMq6Q5ssS3kbTULd7UTKZuD9Wp+7h8zHqB8GoffaIT0Vvl0x\n" +
            "t2TPM9+GJIkS3K+JQOGpPMrT2qRt9sL8J8u2usk/KOiD2uqu0QH3I+0qkvakFc24\n" +
            "sGnj1XmIg46vYEF1N+E8kjzkIKkxoX/1sTKd5EHnw2ivOxLQM3B2PGNAn2N4S9eF\n" +
            "qN+60sNMNXmlptdlVuOxdeJBSeF0vXFZ2cLDgwQTAQoCLQIbAwYLCQgHAwIGFQgC\n" +
            "CQoLBBYCAwECHgECF4ACGQEWIQR/kRb+qQpZg5NsfPqgJ9svPh4RigUCX8giLj4U\n" +
            "gAAAAAASACNwcm9vZkBtZXRhY29kZS5iaXpodHRwczovL2Zvc3N0b2Rvbi5vcmcv\n" +
            "QHZhbml0YXN2aXRhZZAUgAAAAAASAHVwcm9vZkBtZXRhY29kZS5iaXp4bXBwOnZh\n" +
            "bml0YXN2aXRhZUBqYWJiZXJoZWFkLnRrP29tZW1vLXNpZC0yMDkzNjgxNTQ1PTYy\n" +
            "ODlhYTNiZDhhNTAxYTM2MzIyYTBmODk0ZjhkMWQ5NzE4ZGVkMDM2MTYwMzlmMWNm\n" +
            "NDhiMmE0MWVlMzU5MjCPFIAAAAAAEgB0cHJvb2ZAbWV0YWNvZGUuYml6eG1wcDp2\n" +
            "YW5pdGFzdml0YWVAamFiYmVyaGVhZC50az9vbWVtby1zaWQtMTk5MTQxODIwPWY0\n" +
            "YThmZjg0MDA0MzkzYTg3ZjcwMTNjNjAwNjViZGM4OWIxMTY5ZWJjZmI4MDYwYzRm\n" +
            "OTY2OWI0M2JhMGM4MTSQFIAAAAAAEgB1cHJvb2ZAbWV0YWNvZGUuYml6eG1wcDp2\n" +
            "YW5pdGFzdml0YWVAamFiYmVyaGVhZC50az9vbWVtby1zaWQtMTQyOTY3NzEyNT1l\n" +
            "OGE3YjEyMzZiODUwYjQ2N2E1MDkyYzBiZGZlYTg2YTUzZTM2ODQyODNhMWQ1ZmUy\n" +
            "NmVmNTg3MmRkMGFlZjQxAAoJEKAn2y8+HhGKcCkP+gPiUroUSbVfJzFyWej0EPF1\n" +
            "773h5aVoKgZ4gtVYSupM4rudP0oP/tH8sjSFebetpgyKEfZqau3lGbiWaIjXgNRW\n" +
            "+9Tyi201tJbg/sAMczhK9ikGM0RtzI0oA1YK5DFYA8ImCfxkv7ZDi3/AiUzPei/6\n" +
            "ja4g417ueNw8kp12Jh3jErWWHpeideHpcKg9vbbXO9GJ/nNWKXLwBAGhTKNAulby\n" +
            "CYMfXqG1xKiWchDI9BylNF5bSPz5Yoxz91QBAR7X5x77rhSmg0zWkMIbla8VMrzX\n" +
            "ZvfypFMeQeju3qRzLmAsSUr8JCg0q7q9tePQynn/wvcRoPGPxLLEsHdcOM2j5e3G\n" +
            "+jU+gDsOVCpyEYP70OGsF8duR/iNCJ+pso1JPu2I+5NSGeIYfejuoa0AoHUt6yHs\n" +
            "+K2bGh3hEFz8jyxp27GvcQvwAYDDaZ+RQRdAo4DKXb9Y/mqxvrm8GsbB+puzrIxw\n" +
            "be3/iAw47ANJG0RbuDVlycBEwGImAKhQ24fM1/QFhs3YyRPg2jqOujOrcgYVC599\n" +
            "XSGMwcdpS/dka0l77rkMK2WKk1R0+cfwM/XItMti/dVgfMPstfjO3xc8E5LAxZIv\n" +
            "n9yfLIdS87jqgw1mUKF9PSFC53v7cQppYlt6tztFjo8HWisiP7LRkSR+wR+HKjSL\n" +
            "Ek3f6fF97SSUREcxN2cfwsNEBBMBCgHuAhsDBgsJCAcDAgYVCAIJCgsEFgIDAQIe\n" +
            "AQIXgJAUgAAAAAASAHVwcm9vZkBtZXRhY29kZS5iaXp4bXBwOnZhbml0YXN2aXRh\n" +
            "ZUBqYWJiZXJoZWFkLnRrP29tZW1vLXNpZC0xNDI5Njc3MTI1PWU4YTdiMTIzNmI4\n" +
            "NTBiNDY3YTUwOTJjMGJkZmVhODZhNTNlMzY4NDI4M2ExZDVmZTI2ZWY1ODcyZGQw\n" +
            "YWVmNDGPFIAAAAAAEgB0cHJvb2ZAbWV0YWNvZGUuYml6eG1wcDp2YW5pdGFzdml0\n" +
            "YWVAamFiYmVyaGVhZC50az9vbWVtby1zaWQtMTk5MTQxODIwPWY0YThmZjg0MDA0\n" +
            "MzkzYTg3ZjcwMTNjNjAwNjViZGM4OWIxMTY5ZWJjZmI4MDYwYzRmOTY2OWI0M2Jh\n" +
            "MGM4MTSQFIAAAAAAEgB1cHJvb2ZAbWV0YWNvZGUuYml6eG1wcDp2YW5pdGFzdml0\n" +
            "YWVAamFiYmVyaGVhZC50az9vbWVtby1zaWQtMjA5MzY4MTU0NT02Mjg5YWEzYmQ4\n" +
            "YTUwMWEzNjMyMmEwZjg5NGY4ZDFkOTcxOGRlZDAzNjE2MDM5ZjFjZjQ4YjJhNDFl\n" +
            "ZTM1OTIwFiEEf5EW/qkKWYOTbHz6oCfbLz4eEYoFAl/IHp4CGQEACgkQoCfbLz4e\n" +
            "EYqTOA/+OubamE0ivV15sXOLbVTYoPYgy21lJilGXnV7JBcSixRDEupTIaWqZwB4\n" +
            "YVtA8hbyXOMgA96VT0SJ93rN7WDQYCiPjF+oQD2yo24rHxj831SNjPQBjjQiCVtA\n" +
            "aYOvqfgE9peUgAmGxB0JZ9CDCjQFxzV0lAhsb1KlWNNCqTNYqWWlwRdziKeKoUEH\n" +
            "//fiQvWRK7NZbbnNj6rKKo4CnfXKuVCzKDNIeq3vf877k+EIwyNXVlgghFaqTjP8\n" +
            "kUVD0clmtS6fBwZ+LbQydo3yEQ66/mbkjYJ1lpO3hn2hvHXn/kZE7qRmWe/frIMU\n" +
            "Z6niuKaAoPErYQyMTuQ/dFRbsqT6cXHw1mGkuoqiLp6wccb5JrfaszVbUF3MIdZF\n" +
            "041uQqYJvaATgCsM236cgRCpfxlc/8YC2C5PK0oMyYTiHe910PB0aYY1v2IEOnpq\n" +
            "LP+0hdOET0bzTBVwsq9fD4YxNclw4mYHZ439TezI+Fnr47OuIS/BrWWOxBrFdTnL\n" +
            "eHBL42/5+i46jbdE6RKU+Kpb0byWr/jYkm9AZVp1/zHBU31u/TpEFXE/Imn0bauH\n" +
            "ubiBC9L+8Oy4SMrCLdcclfG4Sk3JaBDgetAZLslzxSXEMl9C2tHFSgyO8Xx+5KNK\n" +
            "TZx5n04SWFFUgNZIYATCV70QpVAgagkSrNwrpV2QcfcsFbACiDzCw0EEEwEKAesC\n" +
            "GwMGCwkIBwMCBhUIAgkKCwQWAgMBAh4BAheAFiEEf5EW/qkKWYOTbHz6oCfbLz4e\n" +
            "EYoFAl/IG5qQFIAAAAAAEgB1cHJvb2ZAbWV0YWNvZGUuYml6eG1wcDp2YW5pdGFz\n" +
            "dml0YWVAamFiYmVyaGVhZC50az9vbWVtby1zaWQtMTQyOTY3NzEyNT1lOGE3YjEy\n" +
            "MzZiODUwYjQ2N2E1MDkyYzBiZGZlYTg2YTUzZTM2ODQyODNhMWQ1ZmUyNmVmNTg3\n" +
            "MmRkMGFlZjQxjxSAAAAAABIAdHByb29mQG1ldGFjb2RlLmJpenhtcHA6dmFuaXRh\n" +
            "c3ZpdGFlQGphYmJlcmhlYWQudGs/b21lbW8tc2lkLTE5OTE0MTgyMD1mNGE4ZmY4\n" +
            "NDAwNDM5M2E4N2Y3MDEzYzYwMDY1YmRjODliMTE2OWViY2ZiODA2MGM0Zjk2Njli\n" +
            "NDNiYTBjODE0kBSAAAAAABIAdXByb29mQG1ldGFjb2RlLmJpenhtcHA6dmFuaXRh\n" +
            "c3ZpdGFlQGphYmJlcmhlYWQudGs/b21lbW8tc2lkLTIwOTM2ODE1NDU9NjI4OWFh\n" +
            "M2JkOGE1MDFhMzYzMjJhMGY4OTRmOGQxZDk3MThkZWQwMzYxNjAzOWYxY2Y0OGIy\n" +
            "YTQxZWUzNTkyMAAKCRCgJ9svPh4RioY0EAC2URLKbRQTP97apJ7qctk9dWOKgx+m\n" +
            "xLqCmo0d4uH7phxx6VAXLXCJRwPhrvOekUL4xRC2qYyO0Zit4yXM7HbxqC8lScMX\n" +
            "z98siF7aAXWjJ+2UpIaoP75jpUPs0t0Ude1gQ6UqPqLJI/yQLWVtAaa8IqEFBvFR\n" +
            "sOg4T2MuZdUo75r/PApL1npZcHhNUSwagHYOY6lCKAlpMxitEhxPR07Ji5llIKGV\n" +
            "d1wyOxzP09IXsfeKME2zfrTSf9ybHEVAUQdjybXcEaB+carkw/gzKrxEgrACnEOe\n" +
            "CvWwd0Fq84F9U+MTnikIhdcSTUDAVRbFQQnxdd+G6QocYc15jtdOFnnZvXI9FuWf\n" +
            "asEKlCdqT/bv6a/Nvba0AE9aAIkbCwr3I4Dx93alVPPMBiFpvG6p7mMQLQAL4IsA\n" +
            "m+OinigQy2BtsSd/fwP851QFJNc8aUf9dvu0zq8f/rFNk+V58SEKVXEOtSYK7tcI\n" +
            "A+mrkL/jwkwFas2Uh3ZirkqVq4KFtJA2jlW3m14TTyuk6IGxP5SB5RjTY2nlJbJw\n" +
            "+jO1AkAONomoy0uzuAxlJAFxUjhEpHNU5MuNCYPIlmplkSoCdEv1pc7c1ZnB2zjP\n" +
            "FUqsx69gorhoIEGeMfi1XGxuHy2I3GbmFtA681Vgzl5FppV2v7X9jicL4GruAkwH\n" +
            "zUz1S6VeXnelcMLBjwQTAQIAIgUCV/PW5wIbAwYLCQgHAwIGFQgCCQoLBBYCAwEC\n" +
            "HgECF4AAIQkQoCfbLz4eEYoWIQR/kRb+qQpZg5NsfPqgJ9svPh4RikX2EACFH0OF\n" +
            "okyqKs4hJTeIW5i3nMYID1F3vfusmDFfpcltue+2LdEvrj1rhOXfvOpNSWLWUzJa\n" +
            "O46tH813WSBncMwSlo+6zAkojcOnf0fC08RlDSimioXG4dOcs9pd3TPKxEMOTQYs\n" +
            "kGbyRUrvg6Hl+zv7eXRyyMFMQYAwOQJ9pIf5AGp5ObJ2RU87IOxKH/jTjAV6yDvr\n" +
            "RrBii8NhVr4ouj7c/UflLKLgZ/8RJxcUL5yFInTfbaEMBnQv20AMsAqFR+1VTQ5M\n" +
            "flLfa7eK+g2lPpCXaZaNrzZkdWk6GggAg4A/6Ighx/VxaPY8PI5K0j7C/PUiKSxQ\n" +
            "pHHIwuEOZG4Uy33iOjT6n9oiHSMF3iNbf4zvs1Gv5IJOgv1xgU+ppfLF3o322NTh\n" +
            "t5YXLnbMXPGSh6SvxLlBUxI8gjQdjfaJol0oz31UDedF+CElD7SJbJIPKJq4NBqe\n" +
            "kQjNUFuHNRouXWNjpX5jlTGx8VM4jUzKISo5I1UvGbUZRxteyWWyFJgbr7VCH2+e\n" +
            "aENvN215GHWi63EE8Qkp/euTBqA2U69E6vHxwhw+5NA9zE4J0C9yn1JsqBqjPgpt\n" +
            "emn14QJeJw+yms+BXzAASZY4CL/OGHS40BJgpV7n9GNF8OrZuEZZM+dfzgVd9r4S\n" +
            "Ogq+ogmrA7DvTpM4OA9Cu+wVVXQRL/BNndEdjc0mUGF1bCBTY2hhdWIgPHZhbml0\n" +
            "YXN2aXRhZUBtYWlsYm94Lm9yZz7Cw/4EEwEKAqgCGwMFCwkIBwMFFQoJCAsFFgID\n" +
            "AQACHgECF4AWIQR/kRb+qQpZg5NsfPqgJ9svPh4RigUCYAwbOTUUgAAAAAASABpw\n" +
            "cm9vZkBtZXRhY29kZS5iaXpkbnM6amFiYmVyaGVhZC50az90eXBlPVRYVD4UgAAA\n" +
            "AAASACNwcm9vZkBtZXRhY29kZS5iaXpodHRwczovL2Zvc3N0b2Rvbi5vcmcvQHZh\n" +
            "bml0YXN2aXRhZZAUgAAAAAASAHVwcm9vZkBtZXRhY29kZS5iaXp4bXBwOnZhbml0\n" +
            "YXN2aXRhZUBqYWJiZXJoZWFkLnRrP29tZW1vLXNpZC0yMDkzNjgxNTQ1PTYyODlh\n" +
            "YTNiZDhhNTAxYTM2MzIyYTBmODk0ZjhkMWQ5NzE4ZGVkMDM2MTYwMzlmMWNmNDhi\n" +
            "MmE0MWVlMzU5MjCPFIAAAAAAEgB0cHJvb2ZAbWV0YWNvZGUuYml6eG1wcDp2YW5p\n" +
            "dGFzdml0YWVAamFiYmVyaGVhZC50az9vbWVtby1zaWQtMTk5MTQxODIwPWY0YThm\n" +
            "Zjg0MDA0MzkzYTg3ZjcwMTNjNjAwNjViZGM4OWIxMTY5ZWJjZmI4MDYwYzRmOTY2\n" +
            "OWI0M2JhMGM4MTSQFIAAAAAAEgB1cHJvb2ZAbWV0YWNvZGUuYml6eG1wcDp2YW5p\n" +
            "dGFzdml0YWVAamFiYmVyaGVhZC50az9vbWVtby1zaWQtMTQyOTY3NzEyNT1lOGE3\n" +
            "YjEyMzZiODUwYjQ2N2E1MDkyYzBiZGZlYTg2YTUzZTM2ODQyODNhMWQ1ZmUyNmVm\n" +
            "NTg3MmRkMGFlZjQxSBSAAAAAABIALXByb29mQG1ldGFjb2RlLmJpemh0dHBzOi8v\n" +
            "Y29kZWJlcmcub3JnL3Zhbml0YXN2aXRhZS9naXRlYV9wcm9vZgAKCRCgJ9svPh4R\n" +
            "ivVhD/46gD755fsVTqanw0VUq9HCWEmSGu5jIU6USs8ZD71Jb1uivXjjKVM4Ir8a\n" +
            "BZW7+HNrz+XoRfztExxnwh90GVTWYkdrM44x3dOBxQ33etW41yqkmdHHbDnJ45Oj\n" +
            "23RBp7zSEHmG5TZyvSU5aWUVw+QEqV6uzt43XYL5z3Nnt9RKs9CEAXcrKxOi9FLs\n" +
            "V/g9xARlfsNw5J4LxoTYV856qPabb4VZy/6TRKxWMJXFQg55xODKgMm+Us2C97db\n" +
            "6d4rrGH+XFE5rwKNbJH8m3bsHxEwdleIWX270cwtd769FeAydtjte9kTNNJ+9JGG\n" +
            "Pj2LbhRkf8gnnvQxzyOdiMQ59cAz4rrgVviB0wXOEqhgjxxmIg3e3Y3pncnXRzZm\n" +
            "v2ShxzpUw7UWK25S3TDBVcHRE0IpOm0eOMQq5kWGy+pEUm1IbJz+kPb0cI9x+VhZ\n" +
            "k4nnni4yrhAooBcxn5gkKlQc3FFiM8gqw6duj68ugheL/CtJYuYFdJoKtSajzKSD\n" +
            "vn/64t+rvPY1eywmOgaQ7ljZXEYO3KrgILaKZp5quTY4HY644OMSFboOphLQ2yMm\n" +
            "ZNUMeYKyHNu5Nw6qyrhcpCLEQ8D5RK63YLuvyDIn+psseOCjjNQhjSRTyYfV4cfW\n" +
            "C7Bgs9j14xh7t77CY7OtOjWof2mHSzAerMIr5F698BeqMx9DHsLDyAQTAQoCcgIb\n" +
            "AwULCQgHAwUVCgkICwUWAgMBAAIeAQIXgBYhBH+RFv6pClmDk2x8+qAn2y8+HhGK\n" +
            "BQJfyCO2SBSAAAAAABIALXByb29mQG1ldGFjb2RlLmJpemh0dHBzOi8vY29kZWJl\n" +
            "cmcub3JnL3Zhbml0YXN2aXRhZS9naXRlYV9wcm9vZpAUgAAAAAASAHVwcm9vZkBt\n" +
            "ZXRhY29kZS5iaXp4bXBwOnZhbml0YXN2aXRhZUBqYWJiZXJoZWFkLnRrP29tZW1v\n" +
            "LXNpZC0xNDI5Njc3MTI1PWU4YTdiMTIzNmI4NTBiNDY3YTUwOTJjMGJkZmVhODZh\n" +
            "NTNlMzY4NDI4M2ExZDVmZTI2ZWY1ODcyZGQwYWVmNDGPFIAAAAAAEgB0cHJvb2ZA\n" +
            "bWV0YWNvZGUuYml6eG1wcDp2YW5pdGFzdml0YWVAamFiYmVyaGVhZC50az9vbWVt\n" +
            "by1zaWQtMTk5MTQxODIwPWY0YThmZjg0MDA0MzkzYTg3ZjcwMTNjNjAwNjViZGM4\n" +
            "OWIxMTY5ZWJjZmI4MDYwYzRmOTY2OWI0M2JhMGM4MTSQFIAAAAAAEgB1cHJvb2ZA\n" +
            "bWV0YWNvZGUuYml6eG1wcDp2YW5pdGFzdml0YWVAamFiYmVyaGVhZC50az9vbWVt\n" +
            "by1zaWQtMjA5MzY4MTU0NT02Mjg5YWEzYmQ4YTUwMWEzNjMyMmEwZjg5NGY4ZDFk\n" +
            "OTcxOGRlZDAzNjE2MDM5ZjFjZjQ4YjJhNDFlZTM1OTIwPhSAAAAAABIAI3Byb29m\n" +
            "QG1ldGFjb2RlLmJpemh0dHBzOi8vZm9zc3RvZG9uLm9yZy9AdmFuaXRhc3ZpdGFl\n" +
            "AAoJEKAn2y8+HhGK7R4P/RtmQN/Q39Jj+v4pPWxetHRAqFasLoZnFCj1rYgHE7z1\n" +
            "hWqhCFMaCgeM3r63knwNNQhbZ2KTGhw1tjC/yfWnvDrhQkm1Idr6Zpn9v/D3KIXM\n" +
            "s4bdPMlRUpRXOE/AM+RS08/bouE7CqIwv0oAj3VOMiMazRYLwXAfkJtUzgWNqlwX\n" +
            "pujDtAJB6M11XM/Q6qeM4j1pjvXJs/faUFHXyku1zH4rcR0go79qyAbZ1vS67Ps/\n" +
            "Wg5QYpklc80XarpHRtFVFWagGEtM0mkazkyYBgySZRm8miDGEuwm2HzDru0x+Clp\n" +
            "H7uSDy6uiOjJO6+ApbJxkWDH/POuwpd0fCLwI9C4UAEnZLkCE3iXNbTKguXEc1Rb\n" +
            "t8nxrMVlhQO35+1AVo9rpr/8r+FZRlYfZYEB4sUtxjbbIpFV0YZkOBiAW3r6Tp0X\n" +
            "YJU8wi/fChJvF4j81grwckQavRDbsuQEEbnYzwjucpw2D+Ug/6U+Dhjj1qeYuxJG\n" +
            "VfF+S07d3k2h84IzElcPwoP5uxpe2MdIOQY+EK0D3mpfedmrlkv8wnImMKp9dU2N\n" +
            "tG4YqAikdAy4akbU03nk6GVFrGo3gLDKXBA9GVNbnjW9qd0S3OI64Ci+8mBg3NBN\n" +
            "yIX5uLPsN1+PrwwzQuOBw/gSeWs9JhJA4C8emlzwb+sT8mw+h3ZZ8EI81LD+0h09\n" +
            "wsN/BBMBCgIpAhsDBQsJCAcDBRUKCQgLBRYCAwEAAh4BAheAFiEEf5EW/qkKWYOT\n" +
            "bHz6oCfbLz4eEYoFAl/IIjU+FIAAAAAAEgAjcHJvb2ZAbWV0YWNvZGUuYml6aHR0\n" +
            "cHM6Ly9mb3NzdG9kb24ub3JnL0B2YW5pdGFzdml0YWWQFIAAAAAAEgB1cHJvb2ZA\n" +
            "bWV0YWNvZGUuYml6eG1wcDp2YW5pdGFzdml0YWVAamFiYmVyaGVhZC50az9vbWVt\n" +
            "by1zaWQtMjA5MzY4MTU0NT02Mjg5YWEzYmQ4YTUwMWEzNjMyMmEwZjg5NGY4ZDFk\n" +
            "OTcxOGRlZDAzNjE2MDM5ZjFjZjQ4YjJhNDFlZTM1OTIwjxSAAAAAABIAdHByb29m\n" +
            "QG1ldGFjb2RlLmJpenhtcHA6dmFuaXRhc3ZpdGFlQGphYmJlcmhlYWQudGs/b21l\n" +
            "bW8tc2lkLTE5OTE0MTgyMD1mNGE4ZmY4NDAwNDM5M2E4N2Y3MDEzYzYwMDY1YmRj\n" +
            "ODliMTE2OWViY2ZiODA2MGM0Zjk2NjliNDNiYTBjODE0kBSAAAAAABIAdXByb29m\n" +
            "QG1ldGFjb2RlLmJpenhtcHA6dmFuaXRhc3ZpdGFlQGphYmJlcmhlYWQudGs/b21l\n" +
            "bW8tc2lkLTE0Mjk2NzcxMjU9ZThhN2IxMjM2Yjg1MGI0NjdhNTA5MmMwYmRmZWE4\n" +
            "NmE1M2UzNjg0MjgzYTFkNWZlMjZlZjU4NzJkZDBhZWY0MQAKCRCgJ9svPh4Riuaw\n" +
            "D/9zil7na4utYS7e87CDlnUZT1JmWFRB/fglMG6B3dV1I+wIqsCIYWEkkobJlBI4\n" +
            "YLYqx3UrYn/TGEca6y6pzlhbRk7YaY+z31XSWZj+fuRBZLLx2WTRgH1L3brQn5+k\n" +
            "AHkUx2cS1R1usTxqFqWp+APbdDGDpzvHp8omtaYqecAaOhJp3AN96kdsyXCR/SeY\n" +
            "Kc8aghCBqQx1uhXjyATO3OE+nD/DtWU7z/wqR2LrIvIzrUIQW76FgaqPMSf922p8\n" +
            "1GxFvAHIa81SGptYDPq7kNXqG1LVF/NJBJAqxCZhu/yIrx+jus7+g3XaoEbuGtO/\n" +
            "SPxpdDcKiuRwRer1MznX0cbzE2DoaI21t9kJ3y9l8QBl7xLHSCXYxF+hxBy3w7Nq\n" +
            "TeGpdclC2uMV05H43vKk4Ecrax96g8Bwt6J+jpDPw0LbOBbwGKs5P5ggugtlSFFG\n" +
            "jMmuIfd+s89lhXzTkBirkM8rEcLrORXww1meaxlhZ8gqHP/amWvNIG/Rpoa+oMs2\n" +
            "ArA4BJpSeK58pPKH+kL+uZzbfIHZORM54hnuyDOYiMAjdjETETK4QJuNdHkniEU2\n" +
            "FkHZVYmmdP2Vtjx9XWoFoWjAg2V4XPo87p4GUzwLQ12YS8tNkZMdtUOf0sOKE45E\n" +
            "EhAb4jxjIcWFQdX99YrtG9Pb8H8KlJeMunQwyLGUcbmt7cLDQAQTAQoB6gIbAwUL\n" +
            "CQgHAwUVCgkICwUWAgMBAAIeAQIXgBYhBH+RFv6pClmDk2x8+qAn2y8+HhGKBQJf\n" +
            "yBuakBSAAAAAABIAdXByb29mQG1ldGFjb2RlLmJpenhtcHA6dmFuaXRhc3ZpdGFl\n" +
            "QGphYmJlcmhlYWQudGs/b21lbW8tc2lkLTE0Mjk2NzcxMjU9ZThhN2IxMjM2Yjg1\n" +
            "MGI0NjdhNTA5MmMwYmRmZWE4NmE1M2UzNjg0MjgzYTFkNWZlMjZlZjU4NzJkZDBh\n" +
            "ZWY0MY8UgAAAAAASAHRwcm9vZkBtZXRhY29kZS5iaXp4bXBwOnZhbml0YXN2aXRh\n" +
            "ZUBqYWJiZXJoZWFkLnRrP29tZW1vLXNpZC0xOTkxNDE4MjA9ZjRhOGZmODQwMDQz\n" +
            "OTNhODdmNzAxM2M2MDA2NWJkYzg5YjExNjllYmNmYjgwNjBjNGY5NjY5YjQzYmEw\n" +
            "YzgxNJAUgAAAAAASAHVwcm9vZkBtZXRhY29kZS5iaXp4bXBwOnZhbml0YXN2aXRh\n" +
            "ZUBqYWJiZXJoZWFkLnRrP29tZW1vLXNpZC0yMDkzNjgxNTQ1PTYyODlhYTNiZDhh\n" +
            "NTAxYTM2MzIyYTBmODk0ZjhkMWQ5NzE4ZGVkMDM2MTYwMzlmMWNmNDhiMmE0MWVl\n" +
            "MzU5MjAACgkQoCfbLz4eEYq+WhAAxE+FWFauoqKvk7m9XfV9m1v8o9jzialXMo92\n" +
            "pbyH0TZl2L8H8zUxxJIgvwdgHxvlqLnK95mDNKkRi2qCLhtLVAy04W4n0h7D+//D\n" +
            "5pCbvMokU4LKYWNL8Rtv0cBIFxpUI2xdVdAG5E3pLimdcpE5/IpHAj+ImkF+8rNk\n" +
            "yKUHwTUZ24PKgugdzI5zp0UUZ3QrLe4PxOrZif3UURhzej2751+5GSZixZQN+eWl\n" +
            "L+CldUaWTG4I6e93FpepX3gCpPJo5zMbTlDZG9dQFFMY/jfxNf84MlfDOp5EuIYO\n" +
            "v4QrG1EdYn9xMBdDilK5lWzAh2flQx3Oi2y5jFIGYX8enUJeMrsbtchbcWhS6O/u\n" +
            "fefSAAAriw3r4CLQrJ1eyH5DHK2nh6leNP8hXmiV7c1TzK/KMI8uiDQ13Wp2Utoq\n" +
            "hLVs1tXfM1EMzGoPXQIMDdbOqtJCtjFVlRsBDu/pp1+IppTpq9+ftqHXoB3+nMrh\n" +
            "mV7r2/BMyR+q88PfJGahxQc0w82YZjaMufWfaDIixDpVtRFNSzbWmz7AA+ylOSOv\n" +
            "lJKHpJVHo7YP7h23jhqOc25vZ+JQS1YQ00IYFMg86T/7Xq0gttSYLf2deZHnKF8E\n" +
            "mEoZL0UY2tqOZfXl+Ge+w4QsV01WrXmzcBLydGneACdJ6Luk40kwWO70VEkK+Ed5\n" +
            "u64eyejCwY4EEwEKADgWIQR/kRb+qQpZg5NsfPqgJ9svPh4RigUCXJkXLAIbAwUL\n" +
            "CQgHAwUVCgkICwUWAgMBAAIeAQIXgAAKCRCgJ9svPh4RipPtD/0duXEGR8m82Pbj\n" +
            "zivuW0HCyLIxsbhvWYyBlbENo2qvX+zWl2n4Q24n6nfTOh+6WNLc9MHworhO3laC\n" +
            "9syN4CLgv14cbSCAdTsLaDpOpLBTkwFhEI2gFEiKGaNRnRrf6oGci9q5O4DTkYtk\n" +
            "ARZHq9e0tWA/rYYcsQQrRbj+eG50Lirwn39CwvPlMx5Gag50jThyUb2qbyOXJAkb\n" +
            "7R6UxRvHOKJxjZqW0qp8F5GPBjqRhqcVQ6BypAHsvnhiOtZPiagQSovf6U1gHMU5\n" +
            "kysuybtPMoxesa/U2ZtOs6xvDv2JF+Lscbg/wB1nIe1VwIuzrN80fXB1IGn+Dxl8\n" +
            "hYTFUn7iJuVhPgAkmN4m6+hD6EQcOB+SLO+rJKFNTaVAL4w79onDgVQGJR/FspBI\n" +
            "aHTPUaC3zV8G+91SUFPV37e64+FgPFEGu15UcXJdt3/m1dO/nDu/YU8xC0TMyPk/\n" +
            "llIc+vNl/IxhT0Y8FEHL+WJWZQ9FyBxXBILlP5THuUwnedCuhnlO46GDmZSxHxh7\n" +
            "CoMF19QxMQ6Qf0uDnnr0vMfnYQuwdEcushJHam1XwWe7kvPao0irq1r8tab2BFhP\n" +
            "AnnY+nl4e9S23IkkVbbmCXaRM5QCmwgrLY/XggfcVxqb82qBp8irYHRiIjVAEElB\n" +
            "HJrJWeCQnhVM18nrAbG3ic6sAeB/8s0lUGF1bCBTY2hhdWIgPHZhbml0YXN2aXRh\n" +
            "ZUByaXNldXAubmV0PsLD/gQTAQoCqAIbAwULCQgHAwUVCgkICwUWAgMBAAIeAQIX\n" +
            "gBYhBH+RFv6pClmDk2x8+qAn2y8+HhGKBQJgDBs5NRSAAAAAABIAGnByb29mQG1l\n" +
            "dGFjb2RlLmJpemRuczpqYWJiZXJoZWFkLnRrP3R5cGU9VFhUPhSAAAAAABIAI3By\n" +
            "b29mQG1ldGFjb2RlLmJpemh0dHBzOi8vZm9zc3RvZG9uLm9yZy9AdmFuaXRhc3Zp\n" +
            "dGFlkBSAAAAAABIAdXByb29mQG1ldGFjb2RlLmJpenhtcHA6dmFuaXRhc3ZpdGFl\n" +
            "QGphYmJlcmhlYWQudGs/b21lbW8tc2lkLTIwOTM2ODE1NDU9NjI4OWFhM2JkOGE1\n" +
            "MDFhMzYzMjJhMGY4OTRmOGQxZDk3MThkZWQwMzYxNjAzOWYxY2Y0OGIyYTQxZWUz\n" +
            "NTkyMI8UgAAAAAASAHRwcm9vZkBtZXRhY29kZS5iaXp4bXBwOnZhbml0YXN2aXRh\n" +
            "ZUBqYWJiZXJoZWFkLnRrP29tZW1vLXNpZC0xOTkxNDE4MjA9ZjRhOGZmODQwMDQz\n" +
            "OTNhODdmNzAxM2M2MDA2NWJkYzg5YjExNjllYmNmYjgwNjBjNGY5NjY5YjQzYmEw\n" +
            "YzgxNJAUgAAAAAASAHVwcm9vZkBtZXRhY29kZS5iaXp4bXBwOnZhbml0YXN2aXRh\n" +
            "ZUBqYWJiZXJoZWFkLnRrP29tZW1vLXNpZC0xNDI5Njc3MTI1PWU4YTdiMTIzNmI4\n" +
            "NTBiNDY3YTUwOTJjMGJkZmVhODZhNTNlMzY4NDI4M2ExZDVmZTI2ZWY1ODcyZGQw\n" +
            "YWVmNDFIFIAAAAAAEgAtcHJvb2ZAbWV0YWNvZGUuYml6aHR0cHM6Ly9jb2RlYmVy\n" +
            "Zy5vcmcvdmFuaXRhc3ZpdGFlL2dpdGVhX3Byb29mAAoJEKAn2y8+HhGKwsUP/1o5\n" +
            "+7BMfta1gsVSEBvaqmCZDK0jL7Mo3g2Sayiw+aOVyFUIYy//YLd4QZGIjn7Wq015\n" +
            "pjA/sSwAEtZ3rUE74ACbi29YMqSqgfMBvuD6O3u2TvV0y5I6ozGUkwP2cicNlXxn\n" +
            "cONKBpfDRGa1VDIg4ghGM7/Al4AaBMIhNAQOJS1FiofXZ7qJ7jKK57BY8e1uUfg0\n" +
            "KChPv/xu21wrhKy8DusBz7PSt8S8KBtisst8Mq+ew8rLRFbZ0F/l5VgvdudVSaR1\n" +
            "mmSToRvmKgi2RHjIs7hlEEwRr+dWGO9SaW0oxNbVygMlP/pLEn1R9U94tAxDLXgm\n" +
            "aDYL2NNXwyka5uBKLsy1dHXqXukKPS8py2PZhu2FJMLU0+ml+s2kTbA2Bze7slRO\n" +
            "uiGPJg9WzovCQYVDam8eafGDMC6Q393HXH+gxq29LRg2Lulf4NJtosO4JVbOyzee\n" +
            "Rd5FlZkUiJ7vbiVqIzGN8jel8Mr/NNKCcockwmry1u3JArwgNSqR+Uv+CeH446bm\n" +
            "lfZ6JrwKWQRcuKVRfrXGuT46YmoFSaJjjlTATUVxcUuQNkFlQ6bibmdzEmFaKpVS\n" +
            "QUf8gXnEjLh78K7kdx81c9cmIU4GrulK2uzGQULt3UgKytyrYf5EOwqnbrDDhAYR\n" +
            "FwclbYRjvPUZSlTWoCo4u72gOuxdRWDgya9Ic0YnwsPIBBMBCgJyAhsDBQsJCAcD\n" +
            "BRUKCQgLBRYCAwEAAh4BAheAFiEEf5EW/qkKWYOTbHz6oCfbLz4eEYoFAl/II7ZI\n" +
            "FIAAAAAAEgAtcHJvb2ZAbWV0YWNvZGUuYml6aHR0cHM6Ly9jb2RlYmVyZy5vcmcv\n" +
            "dmFuaXRhc3ZpdGFlL2dpdGVhX3Byb29mkBSAAAAAABIAdXByb29mQG1ldGFjb2Rl\n" +
            "LmJpenhtcHA6dmFuaXRhc3ZpdGFlQGphYmJlcmhlYWQudGs/b21lbW8tc2lkLTE0\n" +
            "Mjk2NzcxMjU9ZThhN2IxMjM2Yjg1MGI0NjdhNTA5MmMwYmRmZWE4NmE1M2UzNjg0\n" +
            "MjgzYTFkNWZlMjZlZjU4NzJkZDBhZWY0MY8UgAAAAAASAHRwcm9vZkBtZXRhY29k\n" +
            "ZS5iaXp4bXBwOnZhbml0YXN2aXRhZUBqYWJiZXJoZWFkLnRrP29tZW1vLXNpZC0x\n" +
            "OTkxNDE4MjA9ZjRhOGZmODQwMDQzOTNhODdmNzAxM2M2MDA2NWJkYzg5YjExNjll\n" +
            "YmNmYjgwNjBjNGY5NjY5YjQzYmEwYzgxNJAUgAAAAAASAHVwcm9vZkBtZXRhY29k\n" +
            "ZS5iaXp4bXBwOnZhbml0YXN2aXRhZUBqYWJiZXJoZWFkLnRrP29tZW1vLXNpZC0y\n" +
            "MDkzNjgxNTQ1PTYyODlhYTNiZDhhNTAxYTM2MzIyYTBmODk0ZjhkMWQ5NzE4ZGVk\n" +
            "MDM2MTYwMzlmMWNmNDhiMmE0MWVlMzU5MjA+FIAAAAAAEgAjcHJvb2ZAbWV0YWNv\n" +
            "ZGUuYml6aHR0cHM6Ly9mb3NzdG9kb24ub3JnL0B2YW5pdGFzdml0YWUACgkQoCfb\n" +
            "Lz4eEYpSJw/+MXSg/xXIpdIVQ3NWeWB3p05op3/ilfb8GuF09XGqck4DeUq6aj93\n" +
            "LD997vFmvL98ypGoyIpe3ds3DoUXzSFVjPLttFcHPsNm2CmkK6L9M1MY/2JzIRPh\n" +
            "9GO1fUe5ZxspXgsf3rTZmkYXRUi/22DrEODm6H6fSK57D9J90ppRe8Rm8rqCV29J\n" +
            "ht1LLgiaCwbz/DKQBBWv5ePaesnyYGTePWqLeHCLsa25mX46NS2HlBSFrcmyR+58\n" +
            "wxnhkXn8SAbm5JCu/FpY5KX0PSY71QDfPUN2BaOoHRHRT5mSxqsgInJHnRVDf66L\n" +
            "Lxh65LnfpdjCjTUsT6WPu7DgO9F8ObYnkno+YiaP7b9Uz7qzV3eK8SwmWTLiGE/x\n" +
            "E1wFGGSvJuvCFAsMGvnc6lVZGA/F3jJCOdBy/QwyfVU54bGjPyUmodZAKoxn6Og2\n" +
            "jylRUL3a9zdzt6sRxeCtuY+eqbq0ZcasP7b3PjYyMOdNQz2k9G0Fz7SW4PPQiu/m\n" +
            "JFuCV33O6X5boaqoO/HTa9ZLJqCA8DjbF4i4r2phVzlv0veskqY1Nl9myGV5Mfq/\n" +
            "El2dc/WfjlZAaw5Hs5qz9vdeFgqu14tSZVdLGENtg4F4TFdLobTE/ElqAVYxyA6e\n" +
            "PsbOVHdIrwnZQmQvDJEoZEumZbXFmDhAm0Rb/9J8kqAd4KH0wIZq/VDCw38EEwEK\n" +
            "AikCGwMFCwkIBwMFFQoJCAsFFgIDAQACHgECF4AWIQR/kRb+qQpZg5NsfPqgJ9sv\n" +
            "Ph4RigUCX8giNT4UgAAAAAASACNwcm9vZkBtZXRhY29kZS5iaXpodHRwczovL2Zv\n" +
            "c3N0b2Rvbi5vcmcvQHZhbml0YXN2aXRhZZAUgAAAAAASAHVwcm9vZkBtZXRhY29k\n" +
            "ZS5iaXp4bXBwOnZhbml0YXN2aXRhZUBqYWJiZXJoZWFkLnRrP29tZW1vLXNpZC0y\n" +
            "MDkzNjgxNTQ1PTYyODlhYTNiZDhhNTAxYTM2MzIyYTBmODk0ZjhkMWQ5NzE4ZGVk\n" +
            "MDM2MTYwMzlmMWNmNDhiMmE0MWVlMzU5MjCPFIAAAAAAEgB0cHJvb2ZAbWV0YWNv\n" +
            "ZGUuYml6eG1wcDp2YW5pdGFzdml0YWVAamFiYmVyaGVhZC50az9vbWVtby1zaWQt\n" +
            "MTk5MTQxODIwPWY0YThmZjg0MDA0MzkzYTg3ZjcwMTNjNjAwNjViZGM4OWIxMTY5\n" +
            "ZWJjZmI4MDYwYzRmOTY2OWI0M2JhMGM4MTSQFIAAAAAAEgB1cHJvb2ZAbWV0YWNv\n" +
            "ZGUuYml6eG1wcDp2YW5pdGFzdml0YWVAamFiYmVyaGVhZC50az9vbWVtby1zaWQt\n" +
            "MTQyOTY3NzEyNT1lOGE3YjEyMzZiODUwYjQ2N2E1MDkyYzBiZGZlYTg2YTUzZTM2\n" +
            "ODQyODNhMWQ1ZmUyNmVmNTg3MmRkMGFlZjQxAAoJEKAn2y8+HhGKNEoP/j/1WwVN\n" +
            "9h17ZpRvz9ZD3e9WN8iwYZnGTvjuAuCJPpCznfEOszP4Gcy/ixPRQXrnAYaqCoFL\n" +
            "08a+dambbFPhGduVgoSkItwNcl6KyPv0Q6dDykXfKXBHSTAdvMmhhL51/f3J0Sxa\n" +
            "xzJ8ev2OzOqJIUzkXtRHwYrdrclJrX/iLankL1lBZzDXJwf+IpAPczBe2a/S/sYz\n" +
            "NAeiH/OvipNpchQQG6lkQF0duzdx1OudbIGQYuWzVtep8uokIJcrVxMleVZLEvfF\n" +
            "ZkR5woOSloTbMfB/Kb1MEL2w9R8trJ5F81ZvXolL/DDIEqLTbZEpP9pUSYLe+eWO\n" +
            "6cszMA2jBwIPYgamg3JKXS/zdDdqnV++rF5/IztLAv1T8mqClOUstU88LuYGBchu\n" +
            "N4hLgeIB+/q0EmCTWIM/ewnMh/KEZHVXJI+ljoMjwS2dZSkV8KcmTVtU1JccR0Ud\n" +
            "HxpYtrcwZaUgzFkPJf3WvFidt7rDs32DJCZiM/NKhzIdukyvG6DAFzabveR8XTlz\n" +
            "evZDNn6gVw04v+jtX++YbasBOI4t8wj2mtqCs3f2bLTRx1fuBu+DyNjAbJT+925G\n" +
            "kbT4gBkb/8aJOOvwWsT4ljXqngXykk39eAVSmRNlsa2Wnv5v/5Fh4gGY5ecfdLH0\n" +
            "z14X/fFoVPkp+g+FOD9lpEP96swULamszCG4wsNABBMBCgHqAhsDBQsJCAcDBRUK\n" +
            "CQgLBRYCAwEAAh4BAheAFiEEf5EW/qkKWYOTbHz6oCfbLz4eEYoFAl/IG5qQFIAA\n" +
            "AAAAEgB1cHJvb2ZAbWV0YWNvZGUuYml6eG1wcDp2YW5pdGFzdml0YWVAamFiYmVy\n" +
            "aGVhZC50az9vbWVtby1zaWQtMTQyOTY3NzEyNT1lOGE3YjEyMzZiODUwYjQ2N2E1\n" +
            "MDkyYzBiZGZlYTg2YTUzZTM2ODQyODNhMWQ1ZmUyNmVmNTg3MmRkMGFlZjQxjxSA\n" +
            "AAAAABIAdHByb29mQG1ldGFjb2RlLmJpenhtcHA6dmFuaXRhc3ZpdGFlQGphYmJl\n" +
            "cmhlYWQudGs/b21lbW8tc2lkLTE5OTE0MTgyMD1mNGE4ZmY4NDAwNDM5M2E4N2Y3\n" +
            "MDEzYzYwMDY1YmRjODliMTE2OWViY2ZiODA2MGM0Zjk2NjliNDNiYTBjODE0kBSA\n" +
            "AAAAABIAdXByb29mQG1ldGFjb2RlLmJpenhtcHA6dmFuaXRhc3ZpdGFlQGphYmJl\n" +
            "cmhlYWQudGs/b21lbW8tc2lkLTIwOTM2ODE1NDU9NjI4OWFhM2JkOGE1MDFhMzYz\n" +
            "MjJhMGY4OTRmOGQxZDk3MThkZWQwMzYxNjAzOWYxY2Y0OGIyYTQxZWUzNTkyMAAK\n" +
            "CRCgJ9svPh4Rijb9D/9LGdGSSD7DhHEd9vMKHe7PL+pysg2K/aTm+XMHKozCOkaf\n" +
            "hnF6ltSW5vjCXOaEnMtKpH5vnb/RL4tKuWLj/CVC0L1rGAa0MQ0b4AG4fWlbctw1\n" +
            "I7PAEES+fUFLftrnMgxYF97gM/yGp9a74IfIKHcZ+sVs7dw9Sa8kDCtg3KBCFG4h\n" +
            "Y5PqUDVlQjWDU0E17y7Vx+0yT9Gfw6esDoao1vCGJhe+AZRZdr5fasdkejUhnZEf\n" +
            "We1NhGbpfQSh92blSu8YxDhM1N0JFL2WOpZ0JVi/N5rYBRsh9gxHSRhsk1xu9EMU\n" +
            "OWORX80bBrvN0md8N4F2SWtuzOz/CpJejrxqvx07lJSW+2nRA9TESg1vdPQxhlBz\n" +
            "NL4HgixHxMhURjPYcvNa8ZPMC40aqukAwt7s/JVMpGwAqOPrCZX3afsbp/OOX3Jp\n" +
            "F5B0V15GNuoDww/yIGAl+7x8QA3L6eDfjgEHtVYKKJEWN/SHak6QN6M4/ku3zsxk\n" +
            "gguhr+hZ+BPXh3+Pk1NGiAKBpo+nnUKBcUpXWV4ie1E8DsNhLGgn2Gci2aTt+CW8\n" +
            "LboPCZJGokhnQhimElUbgZ/8ggsSC6fYqA6qe1EONjw0TSerMJETZqeH/fwJURWN\n" +
            "BH9Yo+cWM7WqG3p8zy1s6ztBMugvZaM8I4C64TtNbjjgwP04lqrPxtvADoZepcLB\n" +
            "jgQTAQoAIQUCV/QFEAIbAwULCQgHAwUVCgkICwUWAgMBAAIeAQIXgAAhCRCgJ9sv\n" +
            "Ph4RihYhBH+RFv6pClmDk2x8+qAn2y8+HhGKs+cQALvEPLUb1jqTtMb/grxritVy\n" +
            "37BKecW5rMgIXnEPY19PU7fpFtehnAiX1Ydg645fGoDuEqSQKXxN3vOpW7RytNgr\n" +
            "JnSB4/a4kJFWctQVbknx99PA3LienS1YcEa48uYTz87RKwYVE8PDVCxqL0+8Q1JE\n" +
            "eaR6xWZfumBJMyBYN5yxhTn2BOQbU09WUwR/lqJc+0Ig1qGSOhpN08MoCqQTpUkY\n" +
            "S9JQ5+jEYfQq0G0FdI/5SoSBB0qS18cs6mkEAwYtQq6DMH54KcnHT1gBwnBgZgPj\n" +
            "J1rclBjVrUS+fBzNznZCXRTFrx8sWamYjeOeJjoBbzX8zpDANqJOwrcFX0qCzVJ+\n" +
            "K7mGIPBQKpDYIV91b94xO0Unp8YBylyQ5WglfLdYlV2wMB9eNkayJHblhQtiQggE\n" +
            "zBfqco+QlhFZjIh8pSON/wnpWlOE0gPUrcHIWkAWxIatPrASpYhQb+I+Ewd6XsJH\n" +
            "oiU/3J3kojdJIoCQgdN3mI8cdORdq8YW0z6ZvFuC9nZp3TW28gut2aDYG9/EPqpW\n" +
            "rLaCrs5qTxiikqd7zEsrexy8roMvr27uCP5gjKXYzNK3NL/xHnignZuBiAM67mNF\n" +
            "jU7wrZHtnFfOPGnuubkpaPS4hMYkZnZc98ELV352sqFyX3dAvnLVHBqzs6SpPMyZ\n" +
            "f+mHlHyFlkU8IXvPmhByzsDNBFfz3OgBDADWLIoatRXvo51XQta+AYScGlwnlB5H\n" +
            "oPnwLfUdE2rly+8zE86omWM24Rf3bBUOwsCNxDotDyupPFJwB5lc+RmFg3AfjZDe\n" +
            "jvr2GEX8CN603z3VuxVqVoUI7uPy+X0UbD5sh6vUJ+SkVBzLejKFWQCvQnVo+U8N\n" +
            "E46lDEIzzWRSr8PSzTUU3ZILbExXb528wzIosaS0m+prGbQJN8jBw7l350y/uqX0\n" +
            "4/NtTGE+x2XJyhgM/jnKzyB8xiY+SYHoMhD3yKnT8uNIHSzgg4fzGCpNGxqR5Zfw\n" +
            "ZX++fCHaog/Uw+j0XvogTTadknVJINkf1wccLzwPhAsre1beIBaac7peMW7yKF4t\n" +
            "TRbTNje2Pjz5A1ZdmITTXL6L/DrUFpaXXukCnfj+AQF1uoSjLzpvJRdalpr6OZhw\n" +
            "HOQrYHbGAeAPh/1Np5m0dWYyidqt7GKh4e66g6B+TJT+LQN5XBy5iyCLiBB6489a\n" +
            "5RmCPXehNm0fOmUY3thmR5tvg5Dn0Z0GxcUAEQEAAcLBvgQYAQgAcgWCX/iQNwkQ\n" +
            "oCfbLz4eEYpHFAAAAAAAHgAgc2FsdEBub3RhdGlvbnMuc2VxdW9pYS1wZ3Aub3Jn\n" +
            "v215/4oD56DA4iFieGJvYIv+F8ITuV/t/0aycU116SYCGwwWIQR/kRb+qQpZg5Ns\n" +
            "fPqgJ9svPh4RigAAN38P/A9xXbD9n3BGT7/LdAbEkhsUDoLR7nB7nlT4lClgGITk\n" +
            "u2rEGHWjsifzV+djuPp+Kf+cWXWVOdhL30AFiYPq8hZejO41npx+H8tA+dIIe22e\n" +
            "mP7JW9IN5K+CRL8XC3XTLnel4ZHAt1z2/ZdXO4bAuU+gOAVNUxOzh2ytbgKex5w8\n" +
            "rtJt1AlaNOVcA7OiZ6OaFIBiPsFaF7ZXYPJlF1STE+2Vwzixb6zr9kZf0lAkGA37\n" +
            "9mxxD5hxjteakAe3bltqJH82XfIaJ03u7sAcZLHthcJJYDiibtAsfzt+nsLxLvDy\n" +
            "uUYx8WmqV17MhvqK0pnYRKk8N6U02XRJ4HaG5X5AkyLqYyYeF1QiOyGFRhp7hwwL\n" +
            "4vQ7RaikFN8xXsj1YviCERjE9CqtZ10cKccEFCHMllR264SeugiKIzf+ed/3ds/i\n" +
            "+Mtd72A8Lr2NIf1vyQ1BzIVLlDhZnRmrmJjgXduwbhhNalayY0lyjbUnc8tSYU+D\n" +
            "V36cCuas1HOTdRoVsCfamIyKLDxQR6hpr780WUX5lTdVS45NGoXfUVcRlUvWN7PD\n" +
            "0fknLO8AdjCFCN8MIfk2jSXDgMi8VPI2AUoz56YnSpQSEVbvtAMKcIhM/5ObqJoY\n" +
            "SNExTUqr5bkiEIcujMrdmPczcrDJtoOyEtlRBJhKRsUY47B/lNWGu3v8YtQ5mWt0\n" +
            "wsF2BBgBAgAJBQJX89zoAhsMACEJEKAn2y8+HhGKFiEEf5EW/qkKWYOTbHz6oCfb\n" +
            "Lz4eEYrgAg//UvHWgBE+nOiW3u3VjwN02OzmYCDk7WUamHqiEc/oxuYcOywMGcg8\n" +
            "XOE47FMWknW5KBJ6DVFuLPd+Ugac/ap4xeZ0KcWnpomr04sgdJYZcNxuJEqTloWS\n" +
            "zMuBU1R43D2KT6f+4tH+LIQ+siitqROoFJhjJEdakWDYamktIUsvX9sW7H5ZqmVq\n" +
            "Cb9mDLc53lERTsrg7Z8abGWTgp8saXiepKLz/9A0fAgV+4NSAahQhjGMHaIhbsJM\n" +
            "jv28ltUHophE0U1X9pIOQLqIDKFVLhSKTmwzKbZGAeFDvnLyn+ARFihC2nB7Ik7x\n" +
            "aAut0Ws1v6uZ1is+VoLgW8QHggxfKI+m2kVxfkrPugrVt+Y9IyQSKWvspxm/AnE0\n" +
            "VZvtz8fmo38fLtvlS3qiqLVB8V0iFGhPvCNH2K9oViz0Zvtk4Q1dIhoF5V9NtA2B\n" +
            "S/J/gC5DDZAxRh9fFj4uEsy2G49Eod6YZGKpRYICWmzbhOeA6f94wY2mT3QQpiWy\n" +
            "PcJR2O5yRX6+iVZ9lYANw75104dqaht7uhyCxLZ8OHk7ujBBHFqJubeOgMNnUMFh\n" +
            "yl3NsPRb2vVuCJ+SpLf4kn/NjO4fTy6AqU0BP+LvhD0bPF3sIIBo9tMHXHBV8X6X\n" +
            "op9cn4kDuvTdxjASZGce4tOVBh4KMhyOqAdeqnfFLZEHt5UGp/of8azOwM0EV/Pb\n" +
            "PwEMANvXotph9BCyrs8NTj1zmaxOvygrc/6HZvb+JiJDaEonyjPEgLoKDePUgdz+\n" +
            "kuWk6d8cSpOm47vBoxf5emVry82htPH9nIGkUyhfFRZkxn7HZ9KIcr+c7NXdBh9M\n" +
            "0Ig1mWRj6bYOJqJHBpRZm+fV9T+CzGlg05IdBv6dFKTSjAv/pjIkAfhuvNEhNGLO\n" +
            "2m/48QeuDzsHjjM80/+V6zNSy4SYw/hPGyTSoU1yJyibtLYP8rRN7x0+qqx3IiyB\n" +
            "NuWZrH6Du6AGffASdk75UiEGr7UVf5ysDx/mBLFMdBoOeSyEHTeypdlC7e8Az7T3\n" +
            "fzEI4+0ibUEV7+EH+94Azn/AVa3vt6WZ+KFgImy6CBM4S2GQmetvTGYRMXosXSzk\n" +
            "5twraPZQoUkEEYy08/4yFEbWBniM3nA472rwXDFyjYxx6UZP+wZ/gaqrQKpgKl7G\n" +
            "Ioe1VVq2bvQpbbWg52K4QpyYmubvfXnGqbjJNXDQN40fK0jVoH3V8pw0czpN0NRA\n" +
            "BgJhhQARAQABwsMVBBgBAgAJBQJX89s/AhsCAcAJEKAn2y8+HhGKwN0gBBkBAgAG\n" +
            "BQJX89s/AAoJENzPszAsnkYVdRkL/j13BrBz0MTnRdYO5Ljd9sN2ryLB1EZFyXqJ\n" +
            "YPZgS0tzy5hWpRvSxH2+N9F3d09LbKLaihuGIApv1XWztIPEhVCtzclIq5rylbsb\n" +
            "flr8yQ5iL/cI4krQjoV1Z8BYhR6rD97UbPXC+yrhmtnJ9YgL/WSivZqIDv3WOHVW\n" +
            "QzlMoLZjBX7hawVODes5MiSkFep+P5s6O7uGLYEwKU0Ss1ohBwFBCpCUlc0cftLX\n" +
            "h8Yo6WxwVRXcsPl0v7095reC+RZtG8DBS8Rhf/of2DOqyQa6qSStIfzjnxQGjWt3\n" +
            "+TQ9RgWtOqC6/wFy5zk818G5wp4nOwcjBnnlbZGKYJqJIWS7BGf9FcVYxzIb+UcC\n" +
            "dQEUB1YX86slkYbznicfsRMvHo8cXGE37wwQVgJ2cgToUQFvMmE2T7Qxz5+5II3v\n" +
            "EXm4lFle+HFFG+rqZXX9S6kgJlm3m+p16GCqV0FX2+9Yl3gKbUFLqgg8j83YagpH\n" +
            "wmteeSTpIc8UttQq2NAw6mLnPFnphRYhBH+RFv6pClmDk2x8+qAn2y8+HhGK570Q\n" +
            "AI9PhyCeAM/Wiq+TodmE85C5L/U6/qS4gSQrqRewD/57fA9O59bg1ntEyz8QW9uH\n" +
            "3Q/5fiE+ck7KI8bLOY6zzC0hTYxszwkgs6hTfRe2z4P6kPJNMyRv6iFKSB0nnA+K\n" +
            "4fMcWnnsGOkA6b97weeFJ5effmM2WCuciPIwf6XMjeewCvyCmZ3tpTlt7nbJ5bVC\n" +
            "QZzp5Dsc5p58g3cTHvomYIeVsojD00kwYZyzRohfYOt+nHWrwVo4/WjNJQUpw+oO\n" +
            "UGVgCqgVgCYTUomzREMaVo8mFe5WR2mo3x7M9DoSfVzALt6qdyJ8lkj0FJUKftJl\n" +
            "WJ0WR8vRXTtwThL25LZ0tFr2drZ99lql+TB4qg8121laRu+GPbWdCQZGH4OjVu3b\n" +
            "ozElF1TceCefGGrk4cDwD46e/pfQVrE7b2oMXx0b0519oQP0YRyTSW8vssgnWaRa\n" +
            "lFWwDDgwBCCB4LbYrlnyauuRvo4KjozCP7ZrzAVbni6i6VSUWIz27FoQsV0BFHLG\n" +
            "42P2fdiPZy5e2CJUuG5XQOkK3ndgZgZYnOJW6RuKB779VY7gia2lkyZJkXHvHGTx\n" +
            "+4glDEAm/O+E7IoANwTIE6N9umdkRk89qtsjSYuGLzBo2yMk80k0MFqQNRlHxskZ\n" +
            "/BE7tydXnOpXhGvlOawIWgfXGwDI0HQhVgdHpPoXl21+zsFNBFf1A1ABEACpA1uS\n" +
            "uwl+3+a6zzwWsvjRAZnLfAe0ibEmvVMoqF/y6m+VDmivoXFEC+a5fCc6qEwcVE1B\n" +
            "AZqvbvklzXhwu0jSrNGKz3Vr3FlwtuS0h6W+EEWTh9B0Y2bNiyB3hqRnZ0KuUMUu\n" +
            "gIifY/G2TPDN3FhCWiU+QJcpTazO+Up74y3YXLxgBo3Zt4H2xf0EzMH9nuKKKtmA\n" +
            "pQTHMnUQu4Bd/AOrWYJgTQqlFwVJZAcggjLcyk5p8QMGyKpwXpXagvwqHgA0Ct+B\n" +
            "YSoYkIpVyywQaUS3PKIeEjp5kCuv5iNlZMDv7A6cHASUqsxpjljEyZ/G+R6S9t+4\n" +
            "7zCNhOqYpAOHrfmXzLe70OtEt91gqIoA6RXeBgBerV/CPuenAjQKQrlcTrlh4/hO\n" +
            "xj3wWfb+HWiatz/rHQI/gN0oZi1Qg3xuaO8VhCQ98MgTszgU1/K2rb54aI4Ar2h3\n" +
            "wajqd+421sGxAe/ftbT4ckHkrCgI0j8t0LPvtoOFjpqh2zMbSRjPRzT6ClY/nYPK\n" +
            "ryY9PZ+6mi8suQpdni4szGKLdIEkloaZNJPwrP7R2d5vQNwyti9qClPeqJjCl5RW\n" +
            "4zj1GP3ZbVUgcFG3FzImTmdyEd4Y9P1hvPa0CV5W+kyzi4P4VeXK6Zk7CcpTu3Pk\n" +
            "2VgfD0qhpYcVQLBqNFtPHl665cRJKMxdore1cwARAQABwsG+BBgBCAByBYJf+JA/\n" +
            "CRCgJ9svPh4RikcUAAAAAAAeACBzYWx0QG5vdGF0aW9ucy5zZXF1b2lhLXBncC5v\n" +
            "cmcpsdpfx97DwXxPD4xmjMokBtXDs8EKClmOHnHi9CVxUgIbDBYhBH+RFv6pClmD\n" +
            "k2x8+qAn2y8+HhGKAAA3xxAAvnU620zS2T3PIPYB2VMv7LoUJfAihwWB9J8L0DZG\n" +
            "tS5GGlFiKQrXaqHpn0cdbm5UrcoXc4gNq78Xn1mG0c3osCmXWqSU/IWovKIubeyn\n" +
            "UfDofUEk3UTNAHOJpdzryclmib8DwueFOKzEWyRVvpfW7FcGj0bD8QBOJ2LgjjvD\n" +
            "gp6jza8RXOwXmMkAUU1Hk9QKJCmLgR5xZ+Jdqcb9iW6rn5o8NOOu4i/FPB0pIT9U\n" +
            "3vXrYWw25uNtoeL89o1xdbFvF+cMOd50x6WtpbAqXtyoSo0giM3ANrY+f9afZBRa\n" +
            "JGnRVdgQoSdmcbLXIOUe1Xu3h4eR35t1i9hGc3krwdz/534Jrqk2MBN0UOFhOPG7\n" +
            "3uJnldrz5YkDH2N9/n6GoMowzj+a2p7VmqvjN1v0WxJHiVGjydaRh09ucAkBWPv4\n" +
            "fOARyZolt6grFP4bLYundxaF/i2XsQDhU3+fXN0PMfkV0EcJT8oinMX3KAknsWLT\n" +
            "1iAWnniL8N+9uYNjKTucmyvYZrNIQc+7mVBPZRJDripistlWX8iFFpJxvf+IOOSE\n" +
            "4zYQGe0LPMImDORQT/8LmgJuwLxvkTfL0QJjEwN6QcDWepy8UforgN3giHt2VZbN\n" +
            "GA+z6+8cu3+wy2phh1tUkQ2XvaJ6x4KnmOR7/Uoio8pTQx6Xt1K0CpXFO7byiJPZ\n" +
            "957CwXYEGAECAAkFAlf1A1ACGwwAIQkQoCfbLz4eEYoWIQR/kRb+qQpZg5NsfPqg\n" +
            "J9svPh4RignwD/9V0MDPMOIOs5TCsn21ww3rzi4tjqZUdG/B6eX4DEU2BzMUvr5K\n" +
            "9Yi8NUf65ua03BQD2PMYWqnGafkJkZ5URAY7iaV7WvJ0SNlJuV2HyGbzqxStiaXO\n" +
            "ntwvGxZpOO6nvg5/uEBtkuzpMG+8716J/MSfyfj2NtdZkMi+2k8PmdK6jvnSsmAP\n" +
            "iuCeP32dZSgnlEa3xiFUkNdpQQNVCnGSNWQ7MpHgl1L94qtv41kGT8LI1b8K4R4l\n" +
            "ovpaKleCCBW9UbD3btHijMLfHy7Ivv4Pg3mkSkEq9uVeNJDkkM2NG7R0dBiclvI5\n" +
            "xVupf2bIHIBqSo8AaMsEFnfhgEcHPqlCErnN+O8PyrVSVP0LwaXKF9mtez2vpd2H\n" +
            "4vhFnHbVKTmVIOsW4B1Mbxhnbvl9CPfqNV4uT+4Vg5WS+XmB+ZYWNIJ6JoBp1fJH\n" +
            "2jUawrQc4DzJPr7ihdeKXd5L+UUo1VmfDRkQvz4Frcwxzl3yg8keHLJd6EvssPtI\n" +
            "0VU5kAgTbmHkRf9vX/4dCvcyk5+PAiSE1A7Xq3uJTZ3FjxXCxEPSLHjM1GCt1+Tm\n" +
            "0pnZVp2bH+jGLmgvoRDGEhmYEfzlMra+7fFD00C3UcbSQDNURs3MtRZzv8EkLLAP\n" +
            "RA7Wcl3XI+M5pFuR+aatDz1hB1uFF/NvnvkjujzTysguoJhU2EKWTtIJIc7BTQRX\n" +
            "89bnARAAs1NzkaHRNHWu2YiQk8lTctciFjyMlVH/Vy28yZSfpHWrt7MCzhkaK1PY\n" +
            "sWlnJifOlCnvzyDW26ouLqbPR51lzRFs9UID1dzg4RCuPMs0TwlIfcUCbBRc3lq3\n" +
            "An941sEwD0+gguGog1oIum2regAftnbSoQj/1+OoZZz0zqeDkHorQcCDTc3EfYsL\n" +
            "jswiFioioOPWgPjG6DSa39xf07YdrW0DOwpJ/M+MCVoPxREqbXC/oCYUQ85h4V66\n" +
            "a8YMYrmkeHzq1kuX7HXuoJKtX8W3vHCiPo/sU/wF74b0oDiskfeXwMaZoRhVPkYG\n" +
            "BEIhAO6n9tqWtuSzxWmMWH/TDw8h2GM6hCa67YPVuiTnztNdr8FR9D3WFpcizpbN\n" +
            "JFj6HBcrfO6IwD5NK8h5fiqFeIQAIfo1PL88OC8jDVjscF0YoJeCiI8sRFjP/1y/\n" +
            "MbYaKIR4fA+PbogeW/klGeI8bp49dGQa+8cnrgDcnzNS1TXh1Zcaob9H+DDHdSCN\n" +
            "37hHtfroFDBCr6KRQ55WzBTdR+zmibZDjkGY4T0uaQjFQAGshPNGcr63rCSWyZnI\n" +
            "nx1H4WWwnsUquTt7T+qt0TAOfd+9shgPqz/dLKkkF87mBtS423dGdDp6BZJ5t4lp\n" +
            "l8LGiSuk9p/ckoB4MET+1iLjaU+FECLFyIg95v6Gk1OYFxeDnnEAEQEAAcLBvgQY\n" +
            "AQgAcgWCX/iQQwkQoCfbLz4eEYpHFAAAAAAAHgAgc2FsdEBub3RhdGlvbnMuc2Vx\n" +
            "dW9pYS1wZ3Aub3JnYWATd/tucGd3FDiHb4AJdZ9NptbAcccakj1mpmFlMEkCGwwW\n" +
            "IQR/kRb+qQpZg5NsfPqgJ9svPh4RigAAMB0P/RLNviscaB3Ii0ZLMs6wQOsYkJ/O\n" +
            "1c4fm8ajmz+Z5lgEhgVbeFhmsqJHIgk/ni4UcdHAsKIBwfcVxZPzR+nH1g5CId/E\n" +
            "2mZXCcCi586Z8jyn8b34Vx/rYdJVkqyBL3OtS+EOMBROvA5VsNWrIVm0BrGqzEjm\n" +
            "0mKUuRldpZyjNRzD2beITJkOCk1H/Vqt+bCXmxb2akb+06bB0NqKG+kjRvlCnSwB\n" +
            "vZ+RyiXVrOeeoj4ODgGyta0W+Rtnoa+AXpr5JE6uBc3Z+vgZrDndqBgD/SZUXjNC\n" +
            "//Y3M6qxfji84e8HXmFzuZccmSzwH+Op6Mlh4XiPhqxmL5/AJoE8QxCUnCb4mENc\n" +
            "nfGdmnlmWGrbApNkdmb3hXDXpZCJzRYgdPtUEuWJ5/mlm0979/bF8b0HN0eCG06V\n" +
            "qoNi+nSNbeth7f/4gseq60DpcJaf4lGVs9AgjXFNGWSyZmHuFwM+UpfHZiRXfprb\n" +
            "ilB7ZBhfhx9d0MZ7luyFAa1IdCjb3bpdvZMPSSx8xoW4obcuExVayJzJz1HCeWwr\n" +
            "3wYuzV4SkWbSm3YWOBfK9EaGc2RogTu89esmyCwW2uslcSrnYS6Dp0lCcC1CXsKl\n" +
            "ZKWV2GZgbZAUI+w7T71UT4Dw/P4qOvuKIfqvD2SJ0ZfoKoV1oa5YNHqpsJUmmc+U\n" +
            "XmfTZgfP14xzBUyVwsF2BBgBAgAJBQJX89bnAhsMACEJEKAn2y8+HhGKFiEEf5EW\n" +
            "/qkKWYOTbHz6oCfbLz4eEYrOhRAA1jBGY2Nrs3SRcou4Ih+4bgXMzG6qPRIh/2ac\n" +
            "lDM86SHyrA4KrsVlsFiRWHndiyHnnqiT2BqX1tJr+FRqCkuzd5dsj3M9hLrG7aqU\n" +
            "rJvoEAAo2A4NY1HofR3rpPbibNKEfkPSY0P9GV+8lzb0wKgJ3tzj1FUqjyT4Q3gm\n" +
            "d9Va7647kHTFJG9Hmjzp/fUkLk4Fg9m3vBg7uaTe0LvF5cgfZk2WGRmqtmOP7hzg\n" +
            "BwJP6fYzzKNeDyFnzUJr4Dba501wQ6YvmKWyh4gvnFNhI95oL9CqgnygsiHUjafQ\n" +
            "WexpmXGWAlPvuUQrGN6352vSFf/g/t00sb+Ic0hp1kohOHsmJmA8BHZPHKZPLPO5\n" +
            "/TvrO/VAd5GMm9iEHkOMAT5sWlnc1oNXHe7QTKpskgUrVjlOKCUkWqeP4Q2oHIVf\n" +
            "2fUtSru0MoqqemqQvPfSzL8XvOnz35JAC/6rDLRWMmhA7bGhLi+K1dQrNH/OQbU3\n" +
            "z3ZwXnlm8NhnuT2Ocu7A9jAfizdA4aHfTVTryzOoLMfO4qOYvmiJsBjnm9qgWMSC\n" +
            "oC5HWI6sD3IxM5J0kgqPWpshyh0pQwvru0yffoP0iyC4Mti+v/5J8XXpAk/QUuRk\n" +
            "Nfd1+cEU3U5Nej8jRfV8gDfe6VZ+7nfI1ALfPaiYPFF4CSb89XE7mX5jJ2cEA4Eg\n" +
            "BlUanyzOwU0EV/UBfwEQAOBVbrr/emeHtuSpxTzNLq6WwLSYROYdhdQ486uDPKEJ\n" +
            "P8S0Vf0OJ4HmX3rYQCFDb0zfZhS/Lu5mFx5Fg4oDGZ0Rlvh4HThnJJGbVZemj4f9\n" +
            "L4p8hD36kaGMCWPBtgg+54HCuQY+pZvqGCuzJtw7K/QHB627ZAuN5xVXAIUXpMvR\n" +
            "VUd3/H6qrSXvEQipVrpBHFVG1YcbX2erj31i5hwd7yGS1nJQfp6hwC5E/GbBWp/u\n" +
            "n9WSKzttKAPls8G81GH6907pmvWvetxJaMqegPpB+tDJ1SESlnRsg7f40x9C7v7o\n" +
            "S3DjyUGbN6AH/aNcktInC4Qly8etoFopsMjvxj/Mpl7NJmokjLmjY2KQxbkQmBiP\n" +
            "Ba6Vi5ulRDzBA7hwVGGnqlNQiP6duNC5NpHhzCZbK8zWSlxB3NRT9KqV6FDezdFa\n" +
            "Xm3rxNrTBl3u/NBP2Gog/0EBukirB7shSWISZ/S7d5MB+YrY4Zg5FRJfW7QwDdhf\n" +
            "b3pwfr+T3TocttcbbExFk4lA0DNMlMyyhNpszxuEUp7rCi3S9Ushu+YIYO2JL0rl\n" +
            "gZzGYLS4IbJmA9/mcxNi/Cl8fC+JVt7o0BNHJ5B8JXupGJN1JWVNkwYIdGoD06ER\n" +
            "hPrre5vuoyjSXK0DRomx07eLi1bxKXHiGd6/GbaJaxToa2+EVIdfKPvoOa8tG7Gb\n" +
            "ABEBAAHCxDwEGAEIAvAFgl/4kFEJEKAn2y8+HhGKRxQAAAAAAB4AIHNhbHRAbm90\n" +
            "YXRpb25zLnNlcXVvaWEtcGdwLm9yZ6QrIsUofls51gJdZ+HVbH8dGKJVka/TmXp6\n" +
            "YORSw2jPAhsCwbygBBkBCABvBYJf+JBRCRBivukmS/FzEUcUAAAAAAAeACBzYWx0\n" +
            "QG5vdGF0aW9ucy5zZXF1b2lhLXBncC5vcmfFq6l7ZWZIJAuffcBu7/dVPtpCFk02\n" +
            "rAl5iGot9GkqNRYhBGo6N12WZ24XXwA6ZmK+6SZL8XMRAAAWGRAAnpBgU8p/MAEW\n" +
            "iHl0LSRV5pUWd+zsxO/FytOEe/ctDtHQ5+bEQLnjRuvsz1De2HuuMvfYFSymjNyx\n" +
            "CxwfdmZ2UA/kCT0CvMo7tn4yhcIvyG/MCAnvERPDgibuJx+SguRhNa8Ld6DDduop\n" +
            "EPyNKwzmnnitP0ar87CQ6sKlMzJH0dduflv7o+Bp0qWfUeagJ1ZDliFu/0AbwFYO\n" +
            "bKJs9M5NFM0aa7V3xWWqVlTjQZA54O3ZlXcbYsnKHwmrD/tBTdyzfBBlMkBWG47b\n" +
            "Og4jJN+p0L5/PQ3VzJgsGAdXgANbkopRTBvg8/+BqtvduOiug/ez3v/ywAkn9Mg6\n" +
            "basjzWC1LLaH019NEwztfZRDVa/kbM0qt+pczra6S6Cr+mOlVm9cw+aHRB93QS2k\n" +
            "MPf9EyliHBRB9AIrvcwY7imVgE1oMr2lDWK3G1OMrlGuF/6YBTI+Ok7lTKpIWpAu\n" +
            "HD9yFK3BzfVnJqmAch54rpTtNZLOQXdFSgUBDjvj5CoQKJ/kdZW6wSNYUHpK8zNd\n" +
            "lL1/pdq9EMQAyNDHN4/LlABLaZFe1Wy/Nn3bAdVYOpd5MpIYN++LyPALbVUIpARg\n" +
            "M9D8LUWTv/PBAMeIvV2MmgrDVIY7wqCdS2WFRqmUfdfeZEPFkfJmNfhWb4YqIhg6\n" +
            "NAfDnE34ddLOqv7FGz4m4Va4sFteztkWIQR/kRb+qQpZg5NsfPqgJ9svPh4RigAA\n" +
            "i1IQAJPs9+RaZW6buMjkKO46eYWkq9/GtiRzp10XZHB3hreezadT4RHw8tqsm6h/\n" +
            "8vprK+eJGfCsnhJz08XuItRZQYa1/XmsGTggQh6n2pmOjP7o1x90b4UdeRYi02k7\n" +
            "wGCwGq6T+yi7jpjWMVEGRn28jumJQmfbC9PjsS0wBI5ne5QFyksu9PjtddYahcov\n" +
            "1Kz/SUvwVUUgLh7TLi/Ll6qrLZb4tRlEGh4rkfM45dsAQv+ekLi4oh0lRoH33lH/\n" +
            "sUSgwnzPyRVeqL8tcy70SkQ5295go5jt/WloXitjlQplbunG1gPQQxfSa+TD71ka\n" +
            "2+wkSBuTyeWHXzi2azOv9gRkUoBOE341cBT16rMIkoIrNLy6uaXj6CtOl6fMqxQz\n" +
            "Jl5wPYk6wccr3i8q4vGfiDZlDO+a8hLljIYF1TC4DThYTY4dwBGlv8dD6vb+Kj5Y\n" +
            "FwhovXVsTzQboinToK58roVOM7TbQAN5OV47sagyIylaACybmEC2jYXmtxYpE3KY\n" +
            "/pKdy8ItBlQRGdIbbS6cPtgUO+SQdjabHkXt6eg355kaXFV9Ci0XjJKsS0az1LXP\n" +
            "ArU8qg40/7M8Bl/ytgmArsHJ4rEYQQxDNSdqh4oH0duSdoSATyyLwrwBYY3a2w1x\n" +
            "V6jX6X3DjiiwxhciYto0C5BFX6uwQIJU6qcrI+qAKt6+rnnqwsOVBBgBAgAJBQJX\n" +
            "9QF/AhsCAkAJEKAn2y8+HhGKwV0gBBkBAgAGBQJX9QF/AAoJEGK+6SZL8XMR13AQ\n" +
            "AKDbc2MFkbJARAU1thZT8nbZMDNxhheaMe4M+1epv1FNxIP5kzxQK06rfwYAW6nf\n" +
            "ms2Bg90FEJXa7KnZqfc5qj+eYPflLYrgcpwR4ZazXykI62RBSHgv9SUNmR9tEOL9\n" +
            "jFd8Qf5x2qbYrCv6ElQmfLee0wrV2ML06nOzkwa71KnKfdCP6dOIa2VyVkQ9TaN6\n" +
            "6yfGfO3qGnpsrd/vHs2Z17a8kTou7wt+Do13TZekbyLnIBG2XkDsY++KzWfNlO4h\n" +
            "svAzyJKbVZfbtiiTwYZdtYWoImn5BQCUaYSGZdkkBgV/eqtXPoLzBieeKC5QTx1A\n" +
            "bO5lz3xAD2iUdj0HN7Uzl4gutnJllLXakhagIRTY6rGSaiBKVhRBTb4ZwFmEB3DA\n" +
            "n9Rd7C1+e5xhtoznDwENC7gCzr37fzW3VbP9rACs1LmMwQEBp8n+az591QDeNFKM\n" +
            "NG9EqtG8vZZY4AER3s+6fzAGFehcj6hnWC7ZUjRpE1oWYLWUWaJ70crBY0X+14QO\n" +
            "YcDCHd0GVg0alhayb/jbcVjUPqNisjX3RUCtKLlw4/auEv4/9fbX1jQogSfmNDp/\n" +
            "gvDUdiUZ5fsq7GpFik2HiNtzITzT1G5QnHQpCwvwttwXdh5TfXPjcWy1OJsnQnht\n" +
            "+X51zOWQnPe4NpayR0CdPAiFBpr+xrwwT0B6i3KJzKcfFiEEf5EW/qkKWYOTbHz6\n" +
            "oCfbLz4eEYoj6w//fcy/NA+hsS9vJmsnQDqJbZMcWJZmImdlXl6MveXYpFR4iwQo\n" +
            "EPY5E2y3N0hzhh4Yy0j9FG7SN3kKH4NysMQSAtgHI9E1sshGCBYSv3DNMsdbSjid\n" +
            "mnGfEcFHl7uSITdhXDMDh84tfDnyF50d0y+Bcpdjb0ipLqDQzV/TISbnsuHC6IVO\n" +
            "T8avF9+NQd2dXMCyxsLQziUuKoB1A+DloAz1HrpmZ5VJ9koebRIV8RIJmIV1Bv4Z\n" +
            "18OBX2XCmWZUXudVMbEI+DTXogenj3j+0yYhalAj14rPndScRkr7NjR3sQxTzygT\n" +
            "Q6k1YGQVitCSFdt90R/UHpBVX8a4bt4giM2ZYnSl0kjkyki7ZtAWMqmgdOks7643\n" +
            "OWrS2IXgTUHy/oikwCpOvtUiV0hGtV7GhIbqecV+jshjXEko/yH/u2JFwjhEnEPP\n" +
            "Njy3gUNb2qtRxqPSboKk+p9OFqGPNonzlgxS4KBRjC+2Lr9ky1VxWhIcsIjMMFxG\n" +
            "STmGCJvwicAAKs1eAyxi3B5ES5taZmkdkZ6niPloFM44EO1cvEPKZLqiXOBlw7J2\n" +
            "fzC53N9HXIdLdEkScbUzxSXQJ2e1nZ1U8pi+hOpRZqNqE+hoAxer9wVzCAljOSwh\n" +
            "wMx2yRO5CAYzX41+jbqspsvqqX/YUCtxzbOAc1VrpvgK0jDlftyZD8q3aE8=\n" +
            "=UC83\n" +
            "-----END PGP PUBLIC KEY BLOCK-----";

    @Test
    public void longAsciiArmoredMessageIsAsciiArmored() throws IOException {
        byte[] asciiArmoredBytes = longAsciiArmoredMessage.getBytes(StandardCharsets.UTF_8);
        assertTrue(asciiArmoredBytes.length > OpenPgpInputStream.MAX_BUFFER_SIZE);
        ByteArrayInputStream asciiIn = new ByteArrayInputStream(asciiArmoredBytes);
        OpenPgpInputStream openPgpInputStream = new OpenPgpInputStream(asciiIn);

        assertTrue(openPgpInputStream.isAsciiArmored());
        assertFalse(openPgpInputStream.isNonOpenPgp());
        assertFalse(openPgpInputStream.isBinaryOpenPgp());

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        Streams.pipeAll(openPgpInputStream, out);

        assertArrayEquals(asciiArmoredBytes, out.toByteArray());
    }

    @Test
    public void shortBinaryOpenPgpMessageIsBinary() throws IOException {
        String asciiArmored = "-----BEGIN PGP MESSAGE-----\n" +
                "\n" +
                "wV4DR2b2udXyHrYSAQdA8GwHRf0XsR9FsPL36oNvdoBZPXddygb2iYdGBJko9X0w\n" +
                "VQqhsjX54WCiMBQx4ma0om49rAWHCk4h4IAq5+WsdN+xCklAUXsbIA7BZUaXfzEB\n" +
                "0j8BpWiU6SJ9YB23OtZSWl/5bu8hx1bnKd5ZM0D5VP2QF772Ci/oAGywSuOA+C6b\n" +
                "G4Bkf1xlQ9vctnBpMix3xUA=\n" +
                "=95Eb\n" +
                "-----END PGP MESSAGE-----\n";
        // Dearmor the data to get binary openpgp data
        ArmoredInputStream armoredInputStream = new ArmoredInputStream(new ByteArrayInputStream(asciiArmored.getBytes(StandardCharsets.UTF_8)));
        ByteArrayOutputStream binaryOut = new ByteArrayOutputStream();
        Streams.pipeAll(armoredInputStream, binaryOut);

        byte[] binaryBytes = binaryOut.toByteArray();
        ByteArrayInputStream binaryIn = new ByteArrayInputStream(binaryBytes);
        OpenPgpInputStream openPgpInputStream = new OpenPgpInputStream(binaryIn);

        assertTrue(openPgpInputStream.isBinaryOpenPgp());
        assertFalse(openPgpInputStream.isAsciiArmored());
        assertFalse(openPgpInputStream.isNonOpenPgp());

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        Streams.pipeAll(openPgpInputStream, out);
        assertArrayEquals(binaryBytes, out.toByteArray());
    }

    @Test
    public void longBinaryOpenPgpMessageIsBinary() throws IOException {
        // Dearmor the data to get binary openpgp data
        ArmoredInputStream armoredInputStream = new ArmoredInputStream(new ByteArrayInputStream(longAsciiArmoredMessage.getBytes(StandardCharsets.UTF_8)));
        ByteArrayOutputStream binaryOut = new ByteArrayOutputStream();
        Streams.pipeAll(armoredInputStream, binaryOut);

        byte[] binaryBytes = binaryOut.toByteArray();
        ByteArrayInputStream binaryIn = new ByteArrayInputStream(binaryBytes);
        OpenPgpInputStream openPgpInputStream = new OpenPgpInputStream(binaryIn);

        assertTrue(openPgpInputStream.isBinaryOpenPgp());
        assertFalse(openPgpInputStream.isAsciiArmored());
        assertFalse(openPgpInputStream.isNonOpenPgp());

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        Streams.pipeAll(openPgpInputStream, out);
        assertArrayEquals(binaryBytes, out.toByteArray());
    }

    @Test
    public void emptyStreamTest() throws IOException {
        ByteArrayInputStream in = new ByteArrayInputStream(new byte[0]);
        OpenPgpInputStream openPgpInputStream = new OpenPgpInputStream(in);

        assertFalse(openPgpInputStream.isBinaryOpenPgp());
        assertFalse(openPgpInputStream.isAsciiArmored());
        assertTrue(openPgpInputStream.isNonOpenPgp());
    }

    @Test
    public void testSignedMessageConsumption() throws PGPException, IOException {
        PGPainless api = PGPainless.getInstance();
        ByteArrayInputStream plaintext = new ByteArrayInputStream("Hello, World!\n".getBytes(StandardCharsets.UTF_8));
        OpenPGPKey secretKeys = api.generateKey()
                .modernKeyRing("Sigmund <sigmund@exmplample.com>");

        ByteArrayOutputStream signedOut = new ByteArrayOutputStream();
        EncryptionStream signer = api.generateMessage()
                .onOutputStream(signedOut)
                .withOptions(ProducerOptions.sign(SigningOptions.get(api)
                                .addSignature(SecretKeyRingProtector.unprotectedKeys(), secretKeys))
                        .setAsciiArmor(false)
                        .overrideCompressionAlgorithm(CompressionAlgorithm.UNCOMPRESSED));

        Streams.pipeAll(plaintext, signer);
        signer.close();

        byte[] binary = signedOut.toByteArray();

        OpenPgpInputStream openPgpIn = new OpenPgpInputStream(new ByteArrayInputStream(binary));
        assertFalse(openPgpIn.isAsciiArmored());
        assertTrue(openPgpIn.isLikelyOpenPgpMessage());
    }
}
