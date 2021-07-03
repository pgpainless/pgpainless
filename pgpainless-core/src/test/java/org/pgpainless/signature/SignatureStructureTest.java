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
package org.pgpainless.signature;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.IOException;
import java.util.List;

import org.bouncycastle.bcpg.sig.NotationData;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.pgpainless.algorithm.HashAlgorithm;
import org.pgpainless.algorithm.PublicKeyAlgorithm;
import org.pgpainless.algorithm.SignatureType;
import org.pgpainless.key.OpenPgpV4Fingerprint;
import org.pgpainless.key.util.KeyIdUtil;
import org.pgpainless.signature.subpackets.SignatureSubpacketsUtil;
import org.pgpainless.util.DateUtil;

public class SignatureStructureTest {

    private static PGPSignature signature;

    @BeforeAll
    public static void parseSignature() throws IOException, PGPException {
        // see https://tests.sequoia-pgp.org/#Detached_signature_with_Subpackets (base case)
        signature = SignatureUtils.readSignatures("-----BEGIN PGP SIGNATURE-----\n" +
                "\n" +
                "wsE7BAABCABlBYJgv4U3RxQAAAAAAB4AIHNhbHRAbm90YXRpb25zLnNlcXVvaWEt\n" +
                "cGdwLm9yZyPTSDcCaeqXuP6nWREE/C94XG6ABwpIlZHM08WewmWgFiEE0aZuGiOx\n" +
                "gsmYD3iM+/zIKgFeczAACgkQ+/zIKgFeczBdoQv+MqOUYG+LA0Sa6P/827ILn9lW\n" +
                "4IQJZVBo/ssvIU0Q8GjvCl4c/kRf+VKSprfkBz+q+vjHI1Ob0rW8amuTvvlSzBQX\n" +
                "6Kb20ahvRYDo445Twuo+/rnp+j5PdRpYITY665AhdwfHSYoEEMhqrEDSQGT8O2xO\n" +
                "1115FJEJaepomY4K9rv2pI8+pX9jOht7sCBK/qkTy/8RC22VyYWoPLSpxldzOBAK\n" +
                "/AcuVCXFGfBt6ybRDXKJJduOVDQ5UFCoC71tq4ah7YmwIMD+/cXYPd+0Xg66U8Eq\n" +
                "3F9MPYCzDYwnhEYZPuHODucHXZ0xpiFRlRkVMZT//+3b4NdOONRf/8sz9YUIMNxB\n" +
                "U2qrEUnByfz3k1ZdkNwn40jYYWHp7hxVmaIDN3v+o5lZfzrKLTWU6wZThZL2FQlf\n" +
                "SqGzjkxOW/c5OcO/EtCUNwIATpou32d1srfK0wGy2ar/o40yezukr5DLTo6B67Hq\n" +
                "Z0D2bD+77247LmD4iuHMHxTI3yv2J+ecfM11Ejir\n" +
                "=pQWH\n" +
                "-----END PGP SIGNATURE-----\n").get(0);
    }

    @Test
    public void testGetSignatureVersion() {
        assertEquals(4, signature.getVersion());
    }

    @Test
    public void testGetSignatureType() {
        assertEquals(SignatureType.BINARY_DOCUMENT, SignatureType.valueOf(signature.getSignatureType()));
    }

    @Test
    public void testGetAlgorithm() {
        assertEquals(PublicKeyAlgorithm.RSA_GENERAL, PublicKeyAlgorithm.fromId(signature.getKeyAlgorithm()));
    }

    @Test
    public void testGetHashAlgorithm() {
        assertEquals(HashAlgorithm.SHA256, HashAlgorithm.fromId(signature.getHashAlgorithm()));
    }

    @Test
    public void testGetSignatureCreationTime() {
        assertEquals(DateUtil.parseUTCDate("2021-06-08 14:56:55 UTC"), signature.getCreationTime());
    }

    @Test
    public void testGetIssuerFingerprint() {
        assertEquals(new OpenPgpV4Fingerprint("D1A66E1A23B182C9980F788CFBFCC82A015E7330"),
                SignatureSubpacketsUtil.getIssuerFingerprintAsOpenPgpV4Fingerprint(signature));
    }

    @Test
    public void testGetIssuer() {
        assertEquals(KeyIdUtil.fromLongKeyId("FBFCC82A015E7330"), SignatureSubpacketsUtil.getIssuerKeyId(signature).getKeyID());
    }

    @Test
    public void testGetNotations() {
        List<NotationData> notations = SignatureSubpacketsUtil.getHashedNotationData(signature, "salt@notations.sequoia-pgp.org");
        assertEquals(1, notations.size());
        NotationData notation = notations.get(0);
        assertEquals("23d348370269ea97b8fea7591104fc2f785c6e80070a489591ccd3c59ec265a0",
                Hex.toHexString(notation.getNotationValueBytes()));
    }

    @Test
    public void testGetSignatureDigestPrefix() {
        assertEquals("5da1", SignatureUtils.getSignatureDigestPrefix(signature));
    }
}
