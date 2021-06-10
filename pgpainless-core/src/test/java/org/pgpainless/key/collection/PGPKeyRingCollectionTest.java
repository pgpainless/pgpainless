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
package org.pgpainless.key.collection;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Collection;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.key.util.KeyRingUtils;

public class PGPKeyRingCollectionTest {

    @Test
    public void constructorThrowsForInvalidInput() throws PGPException, IOException {
        // This is neither a public key, nor a private key
        String invalidKeyRing = "-----BEGIN PGP SIGNATURE-----\n" +
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
                "-----END PGP SIGNATURE-----\n";

        byte[] bytes = invalidKeyRing.getBytes(StandardCharsets.UTF_8);

        // silent = false -> Exception
        assertThrows(PGPException.class, () ->
                new PGPKeyRingCollection(bytes, false));

        // silent = true -> No exception, but not keys either
        PGPKeyRingCollection collection = new PGPKeyRingCollection(bytes, true);
        assertEquals(0, collection.getPgpPublicKeyRingCollection().size());
        assertEquals(0, collection.getPGPSecretKeyRingCollection().size());
    }

    @Test
    public void testConstructorFromCollection() throws PGPException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IOException {
        PGPSecretKeyRing first = PGPainless.generateKeyRing().simpleEcKeyRing("alice@wonderland.lit");
        PGPSecretKeyRing second = PGPainless.generateKeyRing().simpleEcKeyRing("bob@the-builder.tv");
        PGPPublicKeyRing secondPub = KeyRingUtils.publicKeyRingFrom(second);
        Collection<PGPKeyRing> keys = Arrays.asList(first, second, secondPub);

        PGPKeyRingCollection collection = new PGPKeyRingCollection(keys, true);
        assertEquals(2, collection.getPGPSecretKeyRingCollection().size());
        assertEquals(1, collection.getPgpPublicKeyRingCollection().size());
    }
}
