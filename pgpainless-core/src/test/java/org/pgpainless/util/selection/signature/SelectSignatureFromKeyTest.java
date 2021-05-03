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
package org.pgpainless.util.selection.signature;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.io.IOException;
import java.util.Iterator;

import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.signature.SelectSignatureFromKey;

public class SelectSignatureFromKeyTest {

    @Test
    public void validKeyTest() throws IOException {
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
                "bGU+wsFIBBMBCgB8BYJfRGs6AgsJCRD7/MgqAV5zMEcUAAAAAAAeACBzYWx0QG5v\n" +
                "dGF0aW9ucy5zZXF1b2lhLXBncC5vcmfG4smOBDeAPqApuhtNx1qTvcbgFVo/gKVD\n" +
                "bmy8y8ocOwMVCAoCmwECHgEWIQTRpm4aI7GCyZgPeIz7/MgqAV5zMAAA/zwMAKD9\n" +
                "skJhBHzBg0KJKwyaILWlXItDm0Np9GAWTzRa1HWwy4oLzM5tVdi5UiQOO7wsY3r5\n" +
                "NMpkwZrlf7xJzn1lXuonUW3GN/L4MlE8SjjXwvwo7HHDijRa3bs6w6xFi4O21WUL\n" +
                "mi3cwZU0KvGTygW9iTW4bG92KqdejZzyPnJJlmhqhS0rUFKIwGW9OIvIKUmeeeBH\n" +
                "/0zTQBO0zErC73FRekyPTfR3ePuHZ/2VMnd4gI5sBrx9rOLBN/mGU9tBsEAd5Fo0\n" +
                "X0Wgdcm1N7NNcseC0rKFfGjvEah9r/U5NryGjseMPRd+HgogGvuCsAfBcQc4EgbP\n" +
                "4a0aNlrOqJObyOxkOrYofI2f9l0UgHngskF6bTL+LHQ7H49L+gCzbIXJVytHOh+U\n" +
                "7povgQM3OMhG3zNGvxhqgr//k4mDb7G4ygTCOi8lklxkOK/jT3qNHgkoXOWBhKet\n" +
                "AH3aeKnfoChPO/YtZvyZWPW8RcgZkDmyvFyuAuee3YeQbMy4nj2hdgaxYgJ4rs7A\n" +
                "zQRdpZzyAQwA1jC/XGxjK6ddgrRfW9j+s/U00++EvIsgTs2kr3Rg0GP7FLWV0YNt\n" +
                "R1mpl55/bEl7yAxCDTkOgPUMXcaKlnQh6zrlt6H53mF6Bvs3inOHQvOsGtU0dqvb\n" +
                "1vkTF0juLiJgPlM7pWv+pNQ6IA39vKoQsTMBv4v5vYNXP9GgKbg8inUNT17BxzZY\n" +
                "Hfw5+q63ectgDm2on1e8CIRCZ76oBVwzdkVxoy3gjh1eENlk2D4P0uJNZzF1Q8GV\n" +
                "67yLANGMCDICE/OkWn6daipYDzW4iJQtYPUWP4hWhjdm+CK+hg6IQUEn2Vtvi16D\n" +
                "2blRP8BpUNNa4fNuylWVuJV76rIHvsLZ1pbM3LHpRgE8s6jivS3Rz3WRs0TmWCNn\n" +
                "vHPqWizQ3VTy+r3UQVJ5AmhJDrZdZq9iaUIuZ01PoE1+CHiJwuxPtWvVAxf2POcm\n" +
                "1M/F1fK1J0e+lKlQuyonTXqXR22Y41wrfP2aPk3nPSTW2DUAf3vRMZg57ZpRxLEh\n" +
                "EMxcM4/LMR+PABEBAAHCwzwEGAEKAnAFgl9EazoJEPv8yCoBXnMwRxQAAAAAAB4A\n" +
                "IHNhbHRAbm90YXRpb25zLnNlcXVvaWEtcGdwLm9yZ0dWWutVYwZr+KCx8xhv5NSk\n" +
                "pCq2a216Tlbw6NswPnv8ApsCwTygBBkBCgBvBYJfRGs6CRB8L6pN+Tw3skcUAAAA\n" +
                "AAAeACBzYWx0QG5vdGF0aW9ucy5zZXF1b2lhLXBncC5vcmcLUKz5boYqjMRAhrIx\n" +
                "mpikklkNAkNvfSAj/8aFUlIYghYhBB3c4V8JIXzuLzs3YHwvqk35PDeyAAB1wAv/\n" +
                "VGqUIlfFGTGdfraSJ9yqxoCaxmWHtIkwPPVxUcrS/DQaiLd0Bc2tah9f9VHE0wCj\n" +
                "Db7pzk2vugYKrebvskFQaq0S8TwhHQ4n9GVrUnenFf2OAWYfRYmYbENUv+fQm22+\n" +
                "EOxHWSVwB3NWl8albQxs/aPCi3nuPdtdTMU2fHLGDAZ9MGQesb/0tSJLWaqQRvqT\n" +
                "k3llI1OqxGbYLaNXSz6nJDLsKK9v+6lFzxA5C8OOxGikHE7b9RJ6SGVNijItXtHo\n" +
                "rVuAKayDfMKO+0jc25I+agMbfg6p4Ik5D+1LFzZtsSc6Ib6AKu+FLit6Ik74/nrr\n" +
                "/ORSAoTpxnIyJlBu4DS3AUwRd/O7rke8FNVg6EpzaPazrqfY1eZ2YelEE4EO3xXm\n" +
                "wcOLSPVwsLNoC3DdRRLtw5EItZy2z0QiARF+NsUYQQM5RCrQizxuzD5+nXg1AcaE\n" +
                "ixnbju8StB8jT1m4ccJKHsObgi/cIPPsWm5+BUhV9RDLsMWnaVZ8f3tRAHy2TAld\n" +
                "FiEE0aZuGiOxgsmYD3iM+/zIKgFeczAAAAv/DACScy69f/qohzub6e06b3sgmL1K\n" +
                "foCMmFRAiEsDHUHunAb/KWBqkbJ8W6wP0COwh4tbmjUzwexMQyI4m58SLRYULcJ7\n" +
                "kj3axMV0+JJyFoqUpCT06GpqQQIhZY7Y+AHz9FdVNEDjjUwb3mODx8zVyEg57T9C\n" +
                "TfuLrrJDYpycfNJtxYy9qSMPHBiVGqlzqnyETOa312QquZuY6ucfTL8i8kXk5qtL\n" +
                "jVHTnKogzrbTCWuKR8fzsxfZ9afdYXI3SMMsip4Ixx2mLM5tN9IeDI/DQnWetwB2\n" +
                "Z0PEs7UcYcrn6UWs1X4P7jOmtLH+0d96I9ljd9SSmJ9dTr2cV62J/qtK+75hCBk8\n" +
                "Lz+MNWzyAU3sVqGRhsBaLOqvb7K9p3bm6brEmGpBLeKrxuxjBER+7knqkTxSsb+S\n" +
                "msO3lGrEnNEQIlcvoxLIGQiv9b0sblGM9lr40C0D84PEvajhuFAUTItoPfCIVVaT\n" +
                "7Ry8/ZA6t0uQh9/B0hYblb07mJ92hCacoTx+APM=\n" +
                "=yeYe\n" +
                "-----END PGP PUBLIC KEY BLOCK-----";

        PGPPublicKeyRing publicKeys = PGPainless.readKeyRing().publicKeyRing(key);
        Iterator<PGPPublicKey> keyIt = publicKeys.getPublicKeys();
        PGPPublicKey primaryKey = publicKeys.getPublicKey();
        while (keyIt.hasNext()) {
            PGPPublicKey publicKey = keyIt.next();
            if (publicKey == primaryKey) {
                continue;
            }

            boolean validBinding = false;
            Iterator<PGPSignature> signatures = publicKey.getSignatures();
            while (signatures.hasNext()) {
                PGPSignature signature = signatures.next();
                if (SelectSignatureFromKey.isValidSubkeyBindingSignature(primaryKey, publicKey).accept(signature, publicKey, publicKeys)) {
                    validBinding = true;
                }
            }
            assertTrue(validBinding);
        }
    }

    @Test
    public void missingBackSigTest() throws IOException {
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
                "bGU+wsFIBBMBCgB8BYJfRGs6AgsJCRD7/MgqAV5zMEcUAAAAAAAeACBzYWx0QG5v\n" +
                "dGF0aW9ucy5zZXF1b2lhLXBncC5vcmfG4smOBDeAPqApuhtNx1qTvcbgFVo/gKVD\n" +
                "bmy8y8ocOwMVCAoCmwECHgEWIQTRpm4aI7GCyZgPeIz7/MgqAV5zMAAA/zwMAKD9\n" +
                "skJhBHzBg0KJKwyaILWlXItDm0Np9GAWTzRa1HWwy4oLzM5tVdi5UiQOO7wsY3r5\n" +
                "NMpkwZrlf7xJzn1lXuonUW3GN/L4MlE8SjjXwvwo7HHDijRa3bs6w6xFi4O21WUL\n" +
                "mi3cwZU0KvGTygW9iTW4bG92KqdejZzyPnJJlmhqhS0rUFKIwGW9OIvIKUmeeeBH\n" +
                "/0zTQBO0zErC73FRekyPTfR3ePuHZ/2VMnd4gI5sBrx9rOLBN/mGU9tBsEAd5Fo0\n" +
                "X0Wgdcm1N7NNcseC0rKFfGjvEah9r/U5NryGjseMPRd+HgogGvuCsAfBcQc4EgbP\n" +
                "4a0aNlrOqJObyOxkOrYofI2f9l0UgHngskF6bTL+LHQ7H49L+gCzbIXJVytHOh+U\n" +
                "7povgQM3OMhG3zNGvxhqgr//k4mDb7G4ygTCOi8lklxkOK/jT3qNHgkoXOWBhKet\n" +
                "AH3aeKnfoChPO/YtZvyZWPW8RcgZkDmyvFyuAuee3YeQbMy4nj2hdgaxYgJ4rs7A\n" +
                "zQRdpZzyAQwA1jC/XGxjK6ddgrRfW9j+s/U00++EvIsgTs2kr3Rg0GP7FLWV0YNt\n" +
                "R1mpl55/bEl7yAxCDTkOgPUMXcaKlnQh6zrlt6H53mF6Bvs3inOHQvOsGtU0dqvb\n" +
                "1vkTF0juLiJgPlM7pWv+pNQ6IA39vKoQsTMBv4v5vYNXP9GgKbg8inUNT17BxzZY\n" +
                "Hfw5+q63ectgDm2on1e8CIRCZ76oBVwzdkVxoy3gjh1eENlk2D4P0uJNZzF1Q8GV\n" +
                "67yLANGMCDICE/OkWn6daipYDzW4iJQtYPUWP4hWhjdm+CK+hg6IQUEn2Vtvi16D\n" +
                "2blRP8BpUNNa4fNuylWVuJV76rIHvsLZ1pbM3LHpRgE8s6jivS3Rz3WRs0TmWCNn\n" +
                "vHPqWizQ3VTy+r3UQVJ5AmhJDrZdZq9iaUIuZ01PoE1+CHiJwuxPtWvVAxf2POcm\n" +
                "1M/F1fK1J0e+lKlQuyonTXqXR22Y41wrfP2aPk3nPSTW2DUAf3vRMZg57ZpRxLEh\n" +
                "EMxcM4/LMR+PABEBAAHCwT4EGAEKAHIFgl9EazoJEPv8yCoBXnMwRxQAAAAAAB4A\n" +
                "IHNhbHRAbm90YXRpb25zLnNlcXVvaWEtcGdwLm9yZzralcLYPPn2+y5wW/nUhKkM\n" +
                "7cEGJPF1O2wGnOpPUWjdApsCFiEE0aZuGiOxgsmYD3iM+/zIKgFeczAAALEgC/wL\n" +
                "sBjuZAnyh0Pdz2srlUdsp3UKgLo8d32QC5/6nd7SY4WSlfbtSDxcyXt9qbi6dN85\n" +
                "S72cyWfxo2NB8Bi0br/qOuiPcctRxOqrRUye+gQd/9Hd/m/ZmzrTRdqBNAwcQaHE\n" +
                "DRauKwFbvmkK5P/r1W6PfmXYxQ7ORbQhdI74sOZsKoqfkfEhQJd7StjFA1Y+90hG\n" +
                "VQbNuWfp+xJSKc2rilqAt73yt8VJtO7Z/aF6Pw8CxzR7Jj2GfFmrWrfw7GR+jLll\n" +
                "S2QLVQ8/dWfzzv1WTW3c/54dEfz5/vvnLYJB5mUwqXYPF+8gFA0fPA8VdHos/WxL\n" +
                "PfmPe8LxOoS5GHhilfCil9OfDWtb+PdSXQnfRobOjOjzocw7F+eQLWbTTc4FGWTF\n" +
                "UI4yNTzgCY2xtivxu7UpPY2ooD7JlmuzrO7TdC8fhj+l/TEgH67wbhhJgFLoDbwA\n" +
                "+UkgjAOwJ2Rs4Dv77B9o4HUh2Irn72cHy/UsNxkJgoSEkTb30bJJyNlEnds/qyw=\n" +
                "=uSRw\n" +
                "-----END PGP PUBLIC KEY BLOCK-----\n";
        PGPPublicKeyRing publicKeys = PGPainless.readKeyRing().publicKeyRing(key);
        Iterator<PGPPublicKey> keyIt = publicKeys.getPublicKeys();
        PGPPublicKey primaryKey = publicKeys.getPublicKey();
        while (keyIt.hasNext()) {
            PGPPublicKey publicKey = keyIt.next();
            if (publicKey == primaryKey) {
                continue;
            }

            Iterator<PGPSignature> signatures = publicKey.getSignatures();
            while (signatures.hasNext()) {
                PGPSignature signature = signatures.next();
                if (SelectSignatureFromKey.isValidSubkeyBindingSignature(primaryKey, publicKey).accept(signature, publicKey, publicKeys)) {
                    fail("Implementation MUST NOT accept this subkey as bound valid since the backsig is missing.");
                }
            }
        }
    }
}
