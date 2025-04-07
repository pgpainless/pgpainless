// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.encryption_signing;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Date;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.util.io.Streams;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.decryption_verification.ConsumerOptions;
import org.pgpainless.decryption_verification.DecryptionStream;
import org.pgpainless.decryption_verification.MessageMetadata;
import org.pgpainless.exception.KeyException;
import org.pgpainless.util.DateUtil;

public class EncryptionWithMissingKeyFlagsTest {

    private static final String KEY_WITHOUT_KEY_FLAGS = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
            "Version: PGPainless\n" +
            "Comment: A991 A732 9021 7D2D 1250  93C3 2503 6033 1D81 E264\n" +
            "Comment: Test <test@example.org>\n" +
            "\n" +
            "lQcYBGTKPr0BEAC7+3S4hkOwLV4WK3VV+3OALMkVaobplxtyOi/3bZaXC83zh51A\n" +
            "wa5rcZDhMyPKxVZwvuJGQqeeQQQu/n+rCHp3LrDR5J7YTZueQ022xzvvaGZEkT88\n" +
            "rROTdV6FXO0P2CaFlk9dPH6PwHzAWjszdZ6MjPIHkzcSFj6VSHwd4ckOqLGu+LnZ\n" +
            "bqRNwdV+L6HMyCJsMk4O2xkByBb5xDM9kMOy3toVMPj+9i5NS7/lLq/9VK9AstSt\n" +
            "77f5j6cfxsPiSYZAOI9aRg1HLSl3iqQ3o0ZfPNpBv7+nQBcMDkRlzZe+ymcH1ZK3\n" +
            "o/CpAZjfWlSzfMsENlinP/iCAsntGb9YzPtO2fZm/Xjz/8mSkTcM48VFqxKEVUCe\n" +
            "qeoDjNaURx2KjXf1fJKKsYKYpalDgOqmmw2uma02jlMNRbO6JHMdESvVAjReXB7j\n" +
            "oXVwpI660sgdG8Nya8/KhDOpR8Ikr6Gd7J2NH+0N2x25SBFafMP8NFySr3gJdSYE\n" +
            "66Kx8vx/3RWFOXtcrk4Xn2xew6jrHjjdbLO3+92fcyKeHF8jtsYDQQURW0UTDgo6\n" +
            "GSEc3Zz4px73gnU/YmqtPeOiywwuDagnH2ayOwIK5P5a/JgaeST9k4ZTjlBhKm6d\n" +
            "0EXoOy2Ok4zOXB1SAbH6UzevV/20V3/PCN7+zNdn5u4o40uzMIbRxF+9kwARAQAB\n" +
            "AA/9E1Cd0xyUlY8WdO+yhuBRzfs2uW5wffg1QpI2UyrdnMKClFcRsibUcvIVzACI\n" +
            "WRwtVWNU9kQrWzLcqQQkU7YIzfiBrudZ55QTJ8/24GTDRJufr8Q+0PoK92Keu37r\n" +
            "VW6aXVfZlWpoVKvssDT1PUSEwyCeTmdIHXckp2EYbleV5DLdeELSkcPxD5OZifV/\n" +
            "Sf53BFKnkOuJO792ljjxzOMe1eEDsRwO5t+eV/nZte+LTLEoBV1P8K6fYtM+/aBb\n" +
            "iIORJEXLe5/pWwVfFosryWhg4YXr+nJ8e5pgY9rkGJO8gkbjZDuDxOkMNXQBDv4F\n" +
            "6EqrxNCIC733x6AIEHEjUeP/SZM2pwXL7B/j4xwIvf20dvu3tAvLXWbhRXQ1vLYC\n" +
            "xy4yzvwo7+GPKakkkPEWthwRbfengCnEjeEjB54UPditokeVaajZ5ZgG8eBtZ0yS\n" +
            "5SQrFGmz3bXXLKZLWgr5aFoOdkKT35iJUejsiI29IlTdMy/hYgMyt0+vmElmOTqC\n" +
            "PhYYRogYZe8ULxwlApnDOeFCuosppDGs3X45mKO1hnKWnYVvv0F8QFIX6PLB5NE5\n" +
            "tbPIxad7XwYEgZVQlx7r6ob9u5r1mA7/hNykjHRnHRmhYJs4ocuvLXzGD31f0q02\n" +
            "Wz4dQGPKRIhBmPPSwlwr68bzmnDOV8kOMQix8l78FtgYnHEIANOnKJpvk+pT+r/7\n" +
            "0lQYP26keSxbATibFawFVo3Xpp7ujok0I/gYVgiuVXeSFq4KOtRFunBBw0ISBqSB\n" +
            "DCoZh56BIOLBFGP5Kw5sBYyTTf1MmgBc2rxlBBJwO3w3I5l0jcbbIboFYKsVpda6\n" +
            "3wOuYCAFL1Z8WAjoPDiSl0L1tsvpHzOtCufUrxvtWByopdu+3377AWuua/VVyQp0\n" +
            "xwyz2pxd2GcA4APeiNdxICt5DIK/d17U5V7AKx0GcTluLGCqGBOX1lScGi7DAuXv\n" +
            "LAAMNUo+pWErEtuNNc0Weq0/RIL97uCWeaitZhFmQNOYStsN7dlz2aS2//rgPT1w\n" +
            "Mlu0TXEIAONeoBEs7JhqK0AJmLzV3DBNOzNcf9MMupzuRsMoaEHR1ibKKKllRYkE\n" +
            "3JmOupbaVEVWw6lafdY0bkKpRc5pcfW47vWAnb0WhEZloN3HaDLDY7WkI+gWh4zF\n" +
            "ihhmgV2dlV/EwqS9CalkPzKLqWJZM8e5SfTRAOgrGVDB/tOp/pUr0u29qAYS99Fl\n" +
            "Dqo7dYjPccOFI5VZmlwkkrrvV4JIBbIMtN/kAfC0Te72Ka7HqSj3P7amgg0k8KM5\n" +
            "rxXeI4P1fAzFIopa69LXY271XFqnuSfvGXRPQHhIo2WU2t9wh0oYu+3XhbcWUfc0\n" +
            "QGqunPorNwP49x0ESIk2m7jXbqueiUMH/3knMUz84JKoWwnAkYbGipNTVdE0mHJ0\n" +
            "V0CQrNvP5mCU1stXs809UJU93oOnsDAklb/qSFn9jDy2LwHBG0lkV44Si0VPHKa5\n" +
            "83q2yZpvrnipFefccKDgnnhEkz9d5MyLVjnFSO5smpEfeDk9yE3RZIORRxRbnQ4I\n" +
            "Jtd3gy2/GJQADatHsuWa27YswaP9glqEMEtxqqCirn0BaM5TFS+kf+bDpsPaqFcY\n" +
            "zyD2bd1TxlWs+HelhezLwFvsYGryvubZdctM54wfI7v9pMZMXw0qHqQBlZvFZ2p0\n" +
            "FEJV+FLHcBbl+rH+EC0MJ7HufdcT5kVzYt9bRKrnH0WN+0yB3Y2yqdOFXLQXVGVz\n" +
            "dCA8dGVzdEBleGFtcGxlLm9yZz6JAlAEEwEKAEQFAmTKPr0JECUDYDMdgeJkFiEE\n" +
            "qZGnMpAhfS0SUJPDJQNgMx2B4mQCngEFFgIDAQAECwkIBwUVCgkICwWJCWYBfQKZ\n" +
            "AQAAA4sQAKTIO/N+QoqiuaIy28rpesCviltdCYxNAL/jXwrbwfr+D/RIuNKN1jGz\n" +
            "7cQ43YDE+uMJnvnPrXfyP5vxxfzO+ol/EFaXL1X0sLVAKEJzEIPqvZ1zT7i15tGE\n" +
            "wJwjimDXtdRu97PaEZ6YiW86zJcn31LFdAppBMJcMtoY9T7Em4zZoTtbgt/4IY0m\n" +
            "0+hBe/uiNu3j/UNpoD8jKzy+8glJOWPlygb9QZ8o9Ckd9X9PXs7UTP0Fh9ka0HHc\n" +
            "lC3GrDj5gLhrg72WkhNVa3eFVfKIGZuVrdI05LIz+m86WdHD0AZ0wkSn1voOvpYd\n" +
            "bjP+gWCrq27loIPjI7Kv/mdJ9vaXXjtNP8QvZvTnxSI5CxY3GnSiB0OzRQSSpAgH\n" +
            "fFvGXE5bDvQ8g37Yd1QHwSPV4ltxgGzaMMfI6luujkpcNmZC6R214Lr3pZ31qi8G\n" +
            "Lfb7k0QzftuQh5z0vtcFLaUuOz7VGwsHMKnObpoQWq4ynyLbM4oK0fvHgAtF/6Ym\n" +
            "EQNvH6nh5yYEnmWWIie4/2VtkJBRikirjxS2lNJGg/sLYWs08rYCVAipLtttYikD\n" +
            "UT2ejtCUJiI0BesgeGCHxPbdSAC5CmquTqISIDNbOVg3/aZ6vqFi5zAmIz7OGzhc\n" +
            "fm7r2cCw3ZdltPmBCM3qZR8cTWl58NVjSz7VWoLsNcZIk/CUnJgXnQcYBGTKPr4B\n" +
            "EACVef2KJ6VQ/WU32tz1NdFzbN2cfbc4DD5xmqWT6vIEJXq361eDVXuTumVXcORP\n" +
            "oHewz3OMy7ZUZ4i4jcUmGxUVfV9nxYD+Qv547NPcTdlnyx6NfCcy2sLp1EO8k8a0\n" +
            "4v2rzk9UP1k6fD+9aZr9wUoLgox7k49PYBXmqBbeQiuMuav2uGumI5JorOsX7+Mj\n" +
            "PQ7KDoe6s4FlTSOgc64TAkHBvrNLFe+R2hbXG8SNA1QtNSZ2lawctCjIFKT2vVnz\n" +
            "oT3imuEA3DfEJoUva3RWrhBwpql6rP9U8P7/eTMf1rymMcoFvcgMVoE4ZnQ9wUPv\n" +
            "ixdueclYogPbjlpR/uoQmsRKVeLM0+Q7XM0UvGh0FvEg5L5waHW4M7c52y3D5VtY\n" +
            "AsEhWu/ZXN8qk+6L+7crGn+YiKjZrG8bhXR1EEBbNIpM1bb4CBkl1OVtE6jammk0\n" +
            "kN2PDV1tBtMWHwzlgnWuIBXr5b+S3AzrtODSxMYwMgNt7KgEa6PccOgb+doBJjDN\n" +
            "pMQIoTiQX5ynUdxguqKlRosHWXCdy0yUPgzDzOULipFS/X4Gagxw7q67CbJoErVV\n" +
            "VinwTdl7QXhK8tUWuQGVA9ObjVcT94OBhgBjzWQLe255o1VcR4qhn/e81kMRkiua\n" +
            "KkA0C3g8of2sH1MFRE54N61YnQ8P4PZNPYLAjEF0nRT1hQARAQABAA/7BXPGLkBk\n" +
            "9M/RXdizX5Rfd/TcHoWtZbN4oZ8w8/TJcCJH2CaS8hzvnYNah/Z7tXXWd9IRVmzl\n" +
            "0S1XnNe6/blWKwsALGJVYrDh5FpLHgmO6QzNJ/8D1QSKwIm4EMxZHqb69sXXOez3\n" +
            "nb0DfC66cxAWWdYgtq86tnv8QIYYE3JZcVAieCTg9FXu1Led+akL4XCsNe2SwNok\n" +
            "WaQXLRabHmFiMaV5l78Mlobcd2sxX61j6CQ8q22pMgDWTfoGzGM6wTq77aSVmXju\n" +
            "5c475G9odnLx8ZH6s5lU1O3Xd00d8sbb6bn+MvhpsB2FqB+AlPIUPswVhjeWAxAh\n" +
            "0OPf4obIVeO3TiqOy8x2ptPeaLdW/v74U/zainkTdgF59P96d1O68qInqTgOUsCD\n" +
            "QMSsyj+seB32Nz52qW+BqhjUPs4H3ygeqAz8q9Kjo44NRL0YoBZ1Gvfv3UIuKlTA\n" +
            "465J0b8g+XqAC8A4DwxmXIrzQ5o9f3JUHF3arl/Dt+Rcx9VriWU5d9LtldxFGo8u\n" +
            "7RdiEIpFw0ieKBhc8z0hqD227f07Bo51q5gcgG/xfNmKzvgYJGNvsLcdT3J/18nj\n" +
            "abmj/Vuzk2Z16FSv5kh6fWjn7J8GlW8v1d5TMKzVabBgAyENmtYXeMZ6EG5bmbpw\n" +
            "Q79GAAs5w1PPIaAZZnSKhTnVq/4q986ka/EIAL+9js8TZTwWK/h83CWKaOqtTX1V\n" +
            "2U0hKDF839talkdxmZP0sAZHMbkf083jh6bSzjE0Qm25QObL8TECehTzFfstRk9y\n" +
            "sZAjkoLTiH5ZThBu8FjzKzunV5sv7586KeQx6KGFVAv/VuQsj+99Q4UMzrbP+gvH\n" +
            "VYukJSOYKClFPfpsAXJTajHIpVBcKtBQwdSgN5K8fpyDrAg598onKGZ+qlZ4EzJF\n" +
            "hCA66TVidiiMcOu0rgNmYpinL/6WwrjxB34ddcLj3LnJ9DITAlLpGWnveLhO9d6M\n" +
            "VFMdDPezpbGJ93U10utH2b9f4iUmH5NHi2I6VhAtuSV2bOJZAAlfBOwcFP0IAMeS\n" +
            "YgboyyYY41ShZbibyVwNPwRnqopHMxT/5BJTmx1SD33HuZtYYj1TF3CgvUSgZj8M\n" +
            "gnOMgYVm2rFjV0x7TIYuJvPEr7yp/rkq3czmyRnNv7zGun5PTih2GKTh0RL6vhx2\n" +
            "uQ+e9oCDlS9xwnJupkg0b2uT9NC9OSh2jlFgLXl3e1ahKje8T7hyx2pQb8zKO7ir\n" +
            "fXeeFaFgq4uMYXSwE3+oPZkhYppV/mOx094M0XtScqmfPYcCFko21PhqLT52nJkA\n" +
            "yu6b9BenLhSPx2rVlJQrFBvFiqHc1A8Zy1Phou1HwI1B4uhmZzxUs3EdWtyTQFEe\n" +
            "9q2v/ClgfmZnEhUTzSkIAJdINY3Sl72tuI5dFvRcsv0Ypmg9iSJel2pV7S0beCV6\n" +
            "58ihgw5WqULoUZEacnWUhrRMfLUus8CshwfSjP2887GY2/V+1wTxNUOyBPA+ZJPM\n" +
            "EcAQX4mitA474vW7ADYTgGDMasvB7JEYrklRl2YrQbEch/9d2VrQonqVTdw48n09\n" +
            "VBOHCg6XVOEEWwwb3DSbVA8RQd3Tuv0LcBpkre23GvLrPhzcwxEJMlvkiuUk6hBp\n" +
            "tL50ofbgSsZlHOfUpD8FZQ//Jdw8pSiuBVRMiLjowJbR1qApuRG34xdk4pmuLjVG\n" +
            "kqlLOLWdycWufSgPIM1wYN8grEdWNsxu0FaASJNTQYqBf4kCMAQYAQoAGgUCZMo+\n" +
            "vgKeAQUWAgMBAAQLCQgHBRUKCQgLAAoJECUDYDMdgeJk1D4P/2rDvSBMKTUo2RaC\n" +
            "iavhbE84WytNqHaBt5AwY+cqj9WryffA5yqqnOYTYnzxbUK8MFoIgCpRaMIjIue9\n" +
            "IyC6SRxRuvRGGV4nj1zgnCKGxQeIv1QMAsj7b0igVys2D6wwqvfDjwTqkfBpcFb6\n" +
            "OTXkrYD14hYp2Q0fkhHwScReQu3PNnpiYnMqI8prnwIH3hFJfgWQVccYDSEtJPiH\n" +
            "vW4xmWJ2R1NXFuVMMTfVHI7IiTS4yF9NHp0W8OsDbBPK/XhbYFU/VjMOsERhuT+5\n" +
            "9vFydJsBY1s2CieE73qrIhzkG4mdxbH68mA30KbSTW4qb606y1qicuNSjH4f3Wew\n" +
            "vws6REpWo5sMdX3z7mMNrAuWI+jLXmaZqUbxwtQ5YizSXCx2u1xkP6t/c5T1axiY\n" +
            "Oqewjlno7hx5hwHwaDvqdxJulFXWV//7O0R0FvGCqHS+TrpRTEyY+r4yYN9fSp/r\n" +
            "/h5KvL/QspRset6CqQvFlRa5aARYjU0qTb4KwtGHGlaKmDWA9Ipf8U+//dxyDy1+\n" +
            "pWXL5XH+DyfUzpDH5XgPaa05QwX8Wgfk7uYR3IOtVk4cL4B8+O16kIVfQo7geUpQ\n" +
            "heetrKk8fTobRwIu+vN4xWEIqrsX65EmvMWV/DGYmFKHskjKmc7+z8o33/spthHY\n" +
            "lh0k0LBQrX/YNegabaT+3gffzz7/\n" +
            "=TKhx\n" +
            "-----END PGP PRIVATE KEY BLOCK-----";

    // Above key expires in 5 years, so we fix the evaluation date to a known-good value
    private static final Date evaluationDate = DateUtil.parseUTCDate("2023-08-03 12:50:06 UTC");
    private static final String MESSAGE = "Hello, World!\n";

    @Test
    public void testEncryptionForKeyWithoutKeyFlagsFailsByDefault()
            throws IOException {
        PGPSecretKeyRing secretKeys = PGPainless.readKeyRing()
                .secretKeyRing(KEY_WITHOUT_KEY_FLAGS);
        PGPPublicKeyRing publicKeys = PGPainless.extractCertificate(secretKeys);

        assertThrows(KeyException.UnacceptableEncryptionKeyException.class, () ->
                EncryptionOptions.get()
                        .setEvaluationDate(evaluationDate)
                        .addRecipient(publicKeys));
    }


    @Test
    public void testEncryptionForKeyWithoutKeyFlagsSucceedsWithActiveWorkaround()
            throws PGPException, IOException {
        PGPSecretKeyRing secretKeys = PGPainless.readKeyRing()
                .secretKeyRing(KEY_WITHOUT_KEY_FLAGS);
        PGPPublicKeyRing publicKeys = PGPainless.extractCertificate(secretKeys);

        // Prepare encryption
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        EncryptionStream encOut = PGPainless.encryptAndOrSign()
                .onOutputStream(out)
                .withOptions(ProducerOptions.encrypt(EncryptionOptions.get()
                        .setEvaluationDate(evaluationDate)
                        .setAllowEncryptionWithMissingKeyFlags() // Workaround
                        .addRecipient(publicKeys)));

        // Encrypt
        encOut.write(MESSAGE.getBytes(StandardCharsets.UTF_8));
        encOut.close();

        // Prepare decryption
        ByteArrayInputStream in = new ByteArrayInputStream(out.toByteArray());
        DecryptionStream decryptionStream = PGPainless.decryptAndOrVerify()
                .onInputStream(in)
                .withOptions(ConsumerOptions.get()
                        .setAllowDecryptionWithMissingKeyFlags()
                        .addDecryptionKey(secretKeys));
        ByteArrayOutputStream plain = new ByteArrayOutputStream();

        // Decrypt
        Streams.pipeAll(decryptionStream, plain);
        decryptionStream.close();

        // Check result
        assertEquals(MESSAGE, plain.toString());
        MessageMetadata metadata = decryptionStream.getMetadata();
        assertTrue(metadata.isEncryptedFor(publicKeys));
    }
}
