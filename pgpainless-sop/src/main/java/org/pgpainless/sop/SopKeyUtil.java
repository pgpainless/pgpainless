/*
 * Copyright 2020 Paul Schaub.
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
package org.pgpainless.sop;

import static org.pgpainless.sop.Print.err_ln;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.pgpainless.PGPainless;

public class SopKeyUtil {

    public static List<PGPSecretKeyRing> loadKeysFromFiles(File... files) throws IOException, PGPException {
        List<PGPSecretKeyRing> secretKeyRings = new ArrayList<>();
        for (File file : files) {
            try (FileInputStream in = new FileInputStream(file)) {
                secretKeyRings.add(PGPainless.readKeyRing().secretKeyRing(in));
            } catch (PGPException | IOException e) {
                err_ln("Could not load secret key " + file.getName() + ": " + e.getMessage());
                throw e;
            }
        }
        return secretKeyRings;
    }

    public static List<PGPPublicKeyRing> loadCertificatesFromFile(File... files) throws IOException {
        List<PGPPublicKeyRing> publicKeyRings = new ArrayList<>();
        for (File file : files) {
            try (FileInputStream in = new FileInputStream(file)) {
                PGPPublicKeyRingCollection collection = PGPainless.readKeyRing().publicKeyRingCollection(in);
                for (PGPPublicKeyRing keyRing : collection) {
                    publicKeyRings.add(keyRing);
                }
            } catch (IOException | PGPException e) {
                err_ln("Could not read certificate from file " + file.getName() + ": " + e.getMessage());
                throw new IOException(e);
            }
        }
        return publicKeyRings;
    }
}
