/*
 * Copyright 2021 Paul Schaub.
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
package investigations;

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
import org.pgpainless.algorithm.DocumentSignatureType;
import org.pgpainless.decryption_verification.ConsumerOptions;
import org.pgpainless.decryption_verification.DecryptionStream;
import org.pgpainless.encryption_signing.EncryptionOptions;
import org.pgpainless.encryption_signing.EncryptionStream;
import org.pgpainless.encryption_signing.ProducerOptions;
import org.pgpainless.encryption_signing.SigningOptions;
import org.pgpainless.key.protection.SecretKeyRingProtector;
import org.pgpainless.util.ArmorUtils;

public class InvestigateThunderbirdDecryption {

    String OUR_KEY = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
            "Version: PGPainless\n" +
            "Comment: 47D2 3A5E 1455 1FD2 0599  C1FC B57B 5451 9E2D 8FE4\n" +
            "Comment: Alice <alice@pgpainless.org>\n" +
            "\n" +
            "lFgEYP8FlBYJKwYBBAHaRw8BAQdAeJ7fL4TbpSLUJsxGUFnN5MzDZr3lKoKWEO+z\n" +
            "hQEFPqcAAP0T8ED8kcch++7UpcN7qZMP4ihbE9Fu9kp/IKOCZDVwGhF+tBxBbGlj\n" +
            "ZSA8YWxpY2VAcGdwYWlubGVzcy5vcmc+iHgEExYKACAFAmD/BZQCGwEFFgIDAQAE\n" +
            "CwkIBwUVCgkICwIeAQIZAQAKCRC1e1RRni2P5PYqAQC/r4R4RFfVIOPAc16PiffO\n" +
            "GDMzRUYAjIyflvOBIEE//QEAsZGQzIstdIp8gY5CF27pbnnSAA/OGPXbDsNArzPN\n" +
            "tQicXQRg/wWUEgorBgEEAZdVAQUBAQdAFHEP5NzgON0usvHOsTsROojwVTAqgayc\n" +
            "fdPdb597u3UDAQgHAAD/ShtbTmAyZJDjcEDfUNblOogyWntCEgb18Cs5rRm1+agP\n" +
            "mIh1BBgWCgAdBQJg/wWUAhsMBRYCAwEABAsJCAcFFQoJCAsCHgEACgkQtXtUUZ4t\n" +
            "j+SWdwD/cCXm/ufcaIMMOqRw10Lwefc4euOrpFScWA0rUjnK6yEBAMOH1kGHlLbz\n" +
            "mk6D7RbBDdC3aW4xGRjSYBkyhbuxevsDnFgEYP8FlBYJKwYBBAHaRw8BAQdAmuvN\n" +
            "FF+pklSxw3+VVqVu2g2ulpJE7HldtU/Jud/jiEgAAP0RPh7QWqm2hhY6vBNr8fhz\n" +
            "3GBAfZ4A9HxVymuu1M6qMxEdiNUEGBYKAH0FAmD/BZQCGwIFFgIDAQAECwkIBwUV\n" +
            "CgkICwIeAV8gBBkWCgAGBQJg/wWUAAoJEIYvdZaRbR0mBesA/2dxyf9vfRnyrNcm\n" +
            "dguMzYe9oLfD2SU2Sa0jXcURQ+A6AP9uYaehPZvEH0kwdeSi60uCOVznCePrY1mK\n" +
            "M6UEDMPGBwAKCRC1e1RRni2P5J1FAQDhI3tN5C/klh2j8ptQ7ht0LPlbgVU/WmT8\n" +
            "kqejd80WVgEA4dg7MZTk+uzwOWEGIHyxWXRzma9a5k1kM+uxX3RflQU=\n" +
            "=IEzi\n" +
            "-----END PGP PRIVATE KEY BLOCK-----";

    String THEIR_CERT = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
            "Version: FlowCrypt [BUILD_REPLACEABLE_VERSION] Gmail Encryption\n" +
            "Comment: Seamlessly send and receive encrypted email\n" +
            "\n" +
            "xjMEYL/CRRYJKwYBBAHaRw8BAQdAxaJrnD/gWRGqaAVtQ8R9PI0ZGu/YESJ4\n" +
            "HsJeeCxUZOvNF0RlbiA8ZGVuQGZsb3djcnlwdC5jb20+wn4EExYKACYFAmC/\n" +
            "wkUCGwMFFgIDAQAECwkIBwUVCgkICwIeAQIZAQWJAQ/XOQAKCRCGwF2G4DXc\n" +
            "cttHAP9Axna+jmFhZEajILW7BZ8UJpgz7mCC48RMtRj/pre4nQD/bKJXB+sD\n" +
            "zti+tRbi7KNncgkSQeau+Vy/ZnpBUUHBWwjOOARgv8JFEgorBgEEAZdVAQUB\n" +
            "AQdA3dN8Hh18Pqd6OevXWl36y7cM58ZRmUVEEZukXRIholYDAQgHwnUEGBYK\n" +
            "AB0FAmC/wkUCGwwFFgIDAQAECwkIBwUVCgkICwIeAQAKCRCGwF2G4DXcclpK\n" +
            "AQC0uUHWUFNao1Fl85+4c8WecGKsGCihNU9H3q+I1gz22gEAtVo1dWnc0t1f\n" +
            "h1MUYq5FmME+KeFCBZZ9lrMAxRhvigI=\n" +
            "=+XVJ\n" +
            "-----END PGP PUBLIC KEY BLOCK-----\n";

    @Test
    public void generateMessage() throws PGPException, IOException {
        // CHECKSTYLE:OFF
        System.out.println("Decryption Key");
        System.out.println(OUR_KEY);
        // CHECKSTYLE:ON

        PGPSecretKeyRing ourKey = PGPainless.readKeyRing().secretKeyRing(OUR_KEY);
        PGPPublicKeyRing ourCert = PGPainless.extractCertificate(ourKey);
        PGPPublicKeyRing theirCert = PGPainless.readKeyRing().publicKeyRing(THEIR_CERT);

        // CHECKSTYLE:OFF
        System.out.println("Certificate:");
        System.out.println(ArmorUtils.toAsciiArmoredString(ourCert));

        System.out.println("Crypt-Only:");
        // CHECKSTYLE:ON
        ProducerOptions producerOptions = ProducerOptions
                .encrypt(new EncryptionOptions().addRecipient(ourCert).addRecipient(theirCert))
                .setFileName("msg.txt")
                .setModificationDate(new Date());

        generateMessage(producerOptions);

        // CHECKSTYLE:OFF
        System.out.println("Sign-Crypt:");
        // CHECKSTYLE:ON

        producerOptions = ProducerOptions
                .signAndEncrypt(new EncryptionOptions().addRecipient(ourCert).addRecipient(theirCert),
                        new SigningOptions().addInlineSignature(SecretKeyRingProtector.unprotectedKeys(), ourKey, DocumentSignatureType.BINARY_DOCUMENT))
                .setFileName("msg.txt")
                .setModificationDate(new Date());

        generateMessage(producerOptions);
    }

    private void generateMessage(ProducerOptions producerOptions) throws PGPException, IOException {
        String data = "Hello World\n";
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        EncryptionStream encryptionStream = PGPainless.encryptAndOrSign()
                .onOutputStream(out)
                .withOptions(producerOptions);

        Streams.pipeAll(new ByteArrayInputStream(data.getBytes(StandardCharsets.UTF_8)), encryptionStream);
        encryptionStream.close();

        // CHECKSTYLE:OFF
        System.out.println(out);
        // CHECKSTYLE:ON
    }

    @Test
    public void testWithSuspiciousKey() throws PGPException, IOException {
        String KEY = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
                "Comment: 4409 A346 1359 96C9 4595  510E 5A18 53D1 5656 CB7A\n" +
                "Comment: Alice (Created with pgpkeygen.com) <alice@pgpainless.or\n" +
                "\n" +
                "xcLYBGEJRbUBCADdGTnWfMDfZx0Qddc5mpNW1+qMDubfzOoE0bhDMC8UIh+ElET3\n" +
                "N8RgA2RQrFyzlugR7SmN0pa/rWaYmIe8nCRL+/BT8gTzO6HEV5Ya4KPTGCy3SVsp\n" +
                "0ua8fBQBeyF/eBD2hEwPIODtWqjltAHajwU6e/eOsqtC6QS8V6x0vFFjKq+vbOEu\n" +
                "9p9Yxt6jzSWMgLhJR2zRIkvS9Z5hiuz8jhKEWUNAtyhZIOnBYVRYhIWDWTvWMbDk\n" +
                "+pQMoq28eSjFRyxWK7Cdln0H/hBO4kZ3xqOAUNK4B+FrxCDeVfYnlfKwZTBJkkwb\n" +
                "3CkhtscUg54wC/2XCbyih6S1pLnMsNB0WSLZABEBAAEAB/4zYhUvvIL7eGSICobo\n" +
                "D30t+dR708vCl8YMNCwZS0WprWt7PZUQijCUar1hxUjvAMNyxRX67IXVyof1Lz+e\n" +
                "bQA/e2/lJnIRkBp+fad4HBxepvffacgqvmWayNBCbtoAXIg+rkzZ2DeF2eO2LIEg\n" +
                "yMu7hYtpKatFC8/qsIp2/7v/akHRgPZ9QQGg2Sr5RJxZIUbSylrLmILPgTNbVu5+\n" +
                "YTUo8P0IQC7E1FVRmt5EKN3w/6mcOY3Dz8ZtR1312178RnXt9bejjvvdvRRfooRw\n" +
                "wtGr7CWfm8DxJ40GPP287Y2CZXX6ZURwSGCqkmEMPws/SN04qq6plF0pUluUI4re\n" +
                "R3gtBAD10/eebm4wLixXTUNvbXb7PEzWz4gJdBqWc09Zkv8nHyZgrf8DReltFoX8\n" +
                "v/BFjoxXVxUm3C+VP/sjDPDRHsVh4NFvY0nEI4V5jtg0V2gz5pCYoGnryridWARu\n" +
                "FhlVDIaZ00BWmfllLmVMVuDBFqMIddkv7ND6SP6aVXokeV3lJQQA5j9NRj6ZFat/\n" +
                "/vD9iLoXNxShx2bjIvXKyt/emsgay74+37Yzqbysn9XPm6sZcaXAB0DdNwAZKV1z\n" +
                "iaPKbzrPW1dk00+LBuUnFrTlvBB0piOJ0X27hiruLBaZVgx7QnPrsRfEKQX6xKyP\n" +
                "QoP7nE1+AnQpBtVFMtX6AE/Z5SkNCqUEAKXc9iD2Q9c7RkDeCfeUU1bppTSe8Rx2\n" +
                "zroE3v6mrx8+SwLmvE59zGWRW5JtblhRXjJb1M3Z26h8bh3XOGaq3Y6iYkfaBS4y\n" +
                "8BWvmq1yHDMui8sTjyRovhs26nu/PYK06Q1y4AnPbZElDsza3OIShicd6H5udZb9\n" +
                "6XCoNmeGTZseQwzNOUFsaWNlIChDcmVhdGVkIHdpdGggcGdwa2V5Z2VuLmNvbSkg\n" +
                "PGFsaWNlQHBncGFpbmxlc3Mub3JnPsLAhAQTAQoAFwUCYQlFtQIbLwMLCQcDFQoI\n" +
                "Ah4BAheAACEJEFoYU9FWVst6FiEERAmjRhNZlslFlVEOWhhT0VZWy3r8wAgA1BkJ\n" +
                "1DsN0uGUuUq0ENeAZQyHkymgsACJ9CpPkUgY4dDai7jR0XIVgBulOY6HYzoZlkbY\n" +
                "S9PjkDby62Sw21sWwBKrGQubCfJjBIkZxb4uED07t5mkwRgq3B3EuZIZLZS0UlRk\n" +
                "NC2iKpYtWGVd/qq0kE37erJPacX5MececN972gPGD1AlPsz+NFZhxsHBltveEZEb\n" +
                "wuBxg7MF+YumkUc/OzE5znmUhStyLItuI5SI3OU59GXRErUwG9ZjKhsFx/xOM820\n" +
                "m0to5V7psGy9ouBIRhjJKjwzOAkO+WJfey8oMWrHvVMGvPGoyfxBihKreIxUwFYG\n" +
                "ay95kPVg2jbfVOuqP8fC2ARhCUW1AQgAruwAoeYnH1Mv7G+4fuO4qp/UJ7zZF8g5\n" +
                "Jc/1qiX1wTrsubowo9NRPUKL5sG4nQkG4EFfAAEk8UawxyCr2FrFNh1g4+IPor6D\n" +
                "fHC47uRT11sA3I/fGgc4q0cbsXYTpHEgmltkOIWF8a5n6l6pzN5Q5d8oruYkxmKE\n" +
                "eNyn2Uusk6+qWi9IYSY9PnrE7oeRQSqcUUozuv5p8ThY0voYhby1fz6jj0MdaKvm\n" +
                "JnlpJao09IgAU1nT8Hm/H1SbuIiQB1YEyG2oSaHS+B8SnfPFb6Yd/t9gvg7fUh52\n" +
                "4RI7pwdQ/63A+y49IZCWiG5TB9do8/FAO8r55GkOrfAnZIuIvqga2wARAQABAAf9\n" +
                "FVQTc6ozhP9IraSls1si7jMU1E+TjPHN/g1QYBHG2GvN54uLWL5wfm65zkY6s3Mh\n" +
                "UoDGC6MYFQ9QiMc0DOpsd3+3i7HJxEdEkwzPj9lpW63t+fbU9kCBKWk/ODE0je15\n" +
                "UzjnjHjDb0ebxhkKzT8iUBUYydKoE0R58J6/HKC8hzlFWg3ZvKQeqZ+HreP5Avw0\n" +
                "lLpe21AX9ObjUfOjuqfOIra43HnME/6WCSWMat2+tYVAlOo85gOfhBN7vwzgN+4Q\n" +
                "30IjZtxgr0cwsekQg5r96fAAidaQmeQebfMyHGZtFqBwz5iBJpIh/i5HT9rmdVwD\n" +
                "062QY2QXU97ThJx6ms4BkQQA5n4BrpBdD9cDPZXlxFkOqhLB8hQ6l+VHNVg8XPY+\n" +
                "QeLNgTUZG63AlEamPgPXFHHIvHJNsxxIpHJfsZyFQcH8qCc8opxlhHYNzQl1qOHZ\n" +
                "afkpezvCDVgeJm+Zsa6yR3545CmaAVZgHmEkUqqcC9hihCWkI4D/XFX4ASh0y2sM\n" +
                "ajkEAMJHpw5hBEYtH4QY3ANWVpYL8urwpEGg2baP4t9mPxdMc9a9pZ24Zi1UatdQ\n" +
                "A/apxK0MTUNzpogGNYlwiT1k5TzOtuEwC7j5kN9JJsy7DOMFfS1vXQxlTISIGa2j\n" +
                "nJcJyo2PclDGX/Xy7vijo+tW34YNM31UX2PbR7blPT1t/H2zBACVE/SSLud9j5Ps\n" +
                "e7KjXiSdBvqgT5bl6jgtrl9QKVE8ICVnFxekuWtcuHMUfHgum8YhhzdwmpCCReFq\n" +
                "PbaHY5p6OrFmnpJp+3pJjEjFU/2SVf9pVH7g0gQ+zEjyaduxkrCcDJWQ7SToqUlV\n" +
                "vn70MLRmkXGpv1AeC3xUCHqPQoNivjv2wsGbBBgBCgAPBQJhCUW1BQkPCZwAAhsu\n" +
                "AUAJEFoYU9FWVst6wF0gBBkBCgAGBQJhCUW1AAoJEAmePaNkGVibSJMH/29LGkog\n" +
                "uYqwy76kUuqK0sDTOlQ+K9EDbabOvIujN4FN//hju7FU/1U1AmicBbOB2IfXmqwu\n" +
                "ArWHq5JndjrH8oLk6u/weU+/x2t2NaSgM2i8vjAb1QBu7MLiWe4airAuYJ6X8KYC\n" +
                "xhqO2DMCpByyjhCvS5P3idjZM4AHCnozFS7PS1hPsU1LjaAHonfsCbFngBJa1Bpy\n" +
                "Zg/8mDCphYKhqA2K9lZ72r2TTqNQND+yr8R7Ksj9h9qvgHBahFzyT6va+Pd1rIrT\n" +
                "Q4UNH4i4s2bdpF3UW8UauUmeyMp3ozQ5s4q2p7llFB17ul87TiA++DIVms4s3qct\n" +
                "rV+O3VvkaDc8cWgWIQRECaNGE1mWyUWVUQ5aGFPRVlbLetRCCACabiPcOvnELk/F\n" +
                "rdJlqRX+eoyYXFqkXVW7L4ev20SdT3zl7rsr6ExaREhRpACNuR9z80I7vzOqjN2D\n" +
                "QXAnjttsXa09hAGa+1RC546NrG2uMHUTOiXItz5z+S3qI7K2+1XhYyEsBamUfKbP\n" +
                "ymrmW50rcUlaupjDAo9Pfj8pYtkIZN9a8LX2Y5Uj/1e9TUvG/dO8txluL5ow8G5R\n" +
                "q+PWWhoXBThXNyo7C7z3LfikLP+EVqA5VKVSz6xB0apIMIxlZy/LoZBWdoOMQAot\n" +
                "fPz7D/gBblrzEX2St0FZmQBc8RAy1eLqCEXu2b8qgs8TUlkxuuOXzDG5joUI6VFP\n" +
                "Rvm74iZEx8LYBGEJRbUBCADg7LwZ7CI3++geddBBVUdTpG+fVq/spFy0ONTX4HDq\n" +
                "hRa6iRWsG9C39p45WGGKWF3SpXoEeXXT1/TXLUHEJ+R1VOAr/nj1fnki6MHJ1zSO\n" +
                "bS6jH+ybOjA2rHYwmxPbfP9JSf+UgUMO7/X7cPa3QCX9CeXDCLDSiH3Hdi98YY6Y\n" +
                "MwG8gkNw+o3Ot74JjQrQNNt2IMX5NcExr3P+0f0tCZxldukGzJdiEoeqi0eBa7Mo\n" +
                "Mq8qDN8cw8rovBFm81HwW9GXpTmurtw61DOA2LZzP5lrb+nBVwx1GR2YfwD/ZUFg\n" +
                "7DfhqfD5VFtK6zYhxC3GbAQCiRYUtju77M6UolP/h9zbABEBAAEAB/wJdryFZLOd\n" +
                "4moGWhOspA9vvAP8UtPtI49I//koqidmHrpxl9IDH1p9WxGWPRtBjG1KLy8+n/Ou\n" +
                "ua/yG9PgEoOg0jTqdPcW8T7ckqmQug7ajUqAj5fPgjfEHSaN7gB8ZDqDlWr9DyFI\n" +
                "sB0L+tlOpZLTnkZ+GdAC075jFZxy4dHzomGTrc1ouWdX/m9ay5tqKOQyg0EyvDpv\n" +
                "ygQMXOpcEqX5zWn5S12gLdvHU9DY3g7Tb6rLOjHUyVBdnMnngyYupb3iCw60QIor\n" +
                "rgZvqs5ZB3WfYqFMAZRfN1YyzvAgj3AggGMRlGoABdTnnh9qStxPaDewgnqXeVCv\n" +
                "rY9uT0Fu2zahBAD5NMixoHgJocq9HWEUp8i6jKz/jEYwvXjcFWQ6IdJUbHdEQNKp\n" +
                "oVpeQeArX3e7SVGqQXUrJQGsE0tAem2Qb2OUO8aXtTTgqhfgOzaqfbieo36IMI9O\n" +
                "mOFlicu3slaQhg7qDWaDjQCn12F+/VLbwGzz2MRPkQSOd8DFtNvNLB0juwQA5w59\n" +
                "cvGH8OXhCqYs9pjpzDTXRw2ZKa5VhgFiXlzF6/mcvu8qKlND4u2CqbFxR/14Ov8P\n" +
                "dU3aDvcgXuQpgOhZ/rafwjT2fDfTSraMLppVBNJo/FA5G5lPB3d0fNN69/loIuUR\n" +
                "kPB/P6QW6yOsolmAVKgDJymyT9Nl0OeyIFKXSWED/0rfueyhzJ1md6TdV5bhAMW3\n" +
                "kBcqmu6UB1VON357slA6bgmJRIn8zu99/dX3ploWchzWa8bDi+CB5uAVj/ybFsFh\n" +
                "lAXnTAeT7qPMU6GzTxAenQxdKHiG/zt+HOstV7jnjYf/dcCOyG368ZxsBPqtmr4V\n" +
                "AqCe644Pf3+pNKNkTr/5RRnCwZsEGAEKAA8FAmEJRbUFCQ8JnAACGy4BQAkQWhhT\n" +
                "0VZWy3rAXSAEGQEKAAYFAmEJRbUACgkQbJk3aYTh+AiL0QgAn/e+K8B5K+E+ciSR\n" +
                "A0jFfzCJCzqnueDK6rrxbrzk+8roqj9MS9J4V2Mtb/AMRGNTbRjbJfxUbvJaUCcz\n" +
                "n9vKEiggx2ZyS6mr3cMWRxqH2p7s+SENrouUF8tdePRmI8IJT3e74idhblNPrUc0\n" +
                "Wo9Kgzyv4SJqQrt+PG1Yte51O20AULbEkUF4u8ychpY8BJkodxVZENkZsQW+nrr6\n" +
                "YNNp14v2RTCPuvdVmZXNfBVE9TQDigadzcyGUPmfoF9Xr164Cho/ugKgESSYbkMz\n" +
                "kLe4fr5IRoz5aRDNjC4apxHlXrF/yQWWZ9U6CUiqEqUAlgYsNoEC++01I5B4rELg\n" +
                "XO1aYhYhBEQJo0YTWZbJRZVRDloYU9FWVst6WHIH+wTajug9UQiNTyMZ8PAk0cHr\n" +
                "miEaydBUdAWyZ6EKNsBgkamVSEOw9nPnDuGzZzcMOGwHfQ78CmoCniP44prMoRiS\n" +
                "PcfmdFeQDt5kAKg1offUe6z36Brtk/8HO3FCbKM+zim2YF7GNLuCZTfZfYp1B0Gv\n" +
                "/Ici5zjrJIFR/78vcZgjpEzUCQ2XkgFTNNuWsGJ7APm6MPzQLEyK6apVw0BoM+Mb\n" +
                "vt8V+lJV+hZNzEWQmbuiyv87onWNJGDQiu30bXktaHx6VEjjwjicPqv4qDNT3rhv\n" +
                "dsB/NddWOgRXfnZ833hVT6rBZYtm+nqb3nm8rbJOtPi/MnEFoyWFi3uT9h7oeAc=\n" +
                "=Zaty\n" +
                "-----END PGP PRIVATE KEY BLOCK-----\n";
        PGPSecretKeyRing secretKey = PGPainless.readKeyRing().secretKeyRing(KEY);
        PGPPublicKeyRing publicKey = PGPainless.extractCertificate(secretKey);

        ByteArrayInputStream data = new ByteArrayInputStream("Hello, World!\n".getBytes(StandardCharsets.UTF_8));
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        EncryptionStream encryptionStream = PGPainless.encryptAndOrSign().onOutputStream(out)
                .withOptions(ProducerOptions.signAndEncrypt(
                        EncryptionOptions.encryptCommunications()
                                .addRecipient(publicKey),
                        SigningOptions.get()
                                .addInlineSignature(SecretKeyRingProtector.unprotectedKeys(), secretKey, DocumentSignatureType.BINARY_DOCUMENT)
                ).setAsciiArmor(true));

        Streams.pipeAll(data, encryptionStream);
        encryptionStream.close();
        // CHECKSTYLE:OFF
        System.out.println(out);
        // CHECKSTYLE:ON

        ByteArrayInputStream in = new ByteArrayInputStream(out.toByteArray());
        ByteArrayOutputStream clear = new ByteArrayOutputStream();

        DecryptionStream decryptionStream = PGPainless.decryptAndOrVerify()
                .onInputStream(in)
                .withOptions(new ConsumerOptions()
                        .addDecryptionKey(secretKey, SecretKeyRingProtector.unprotectedKeys())
                        .addVerificationCert(publicKey));

        Streams.pipeAll(decryptionStream, clear);

        decryptionStream.close();
        // CHECKSTYLE:OFF
        System.out.println(clear);
        // CHECKSTYLE:ON
    }
}
