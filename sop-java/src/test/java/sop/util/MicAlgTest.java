// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package sop.util;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.HashMap;
import java.util.Map;

import org.junit.jupiter.api.Test;
import sop.MicAlg;

public class MicAlgTest {

    @Test
    public void constructorNullArgThrows() {
        assertThrows(IllegalArgumentException.class, () -> new MicAlg(null));
    }

    @Test
    public void emptyMicAlgIsEmptyString() {
        MicAlg empty = MicAlg.empty();
        assertNotNull(empty.getMicAlg());
        assertTrue(empty.getMicAlg().isEmpty());
    }

    @Test
    public void fromInvalidAlgorithmIdThrows() {
        assertThrows(IllegalArgumentException.class, () -> MicAlg.fromHashAlgorithmId(-1));
    }

    @Test
    public void fromHashAlgorithmIdsKnownAlgsMatch() {
        Map<Integer, String> knownAlgorithmMicalgs = new HashMap<>();
        knownAlgorithmMicalgs.put(1, "pgp-md5");
        knownAlgorithmMicalgs.put(2, "pgp-sha1");
        knownAlgorithmMicalgs.put(3, "pgp-ripemd160");
        knownAlgorithmMicalgs.put(8, "pgp-sha256");
        knownAlgorithmMicalgs.put(9, "pgp-sha384");
        knownAlgorithmMicalgs.put(10, "pgp-sha512");
        knownAlgorithmMicalgs.put(11, "pgp-sha224");

        for (Integer id : knownAlgorithmMicalgs.keySet()) {
            MicAlg micAlg = MicAlg.fromHashAlgorithmId(id);
            assertEquals(knownAlgorithmMicalgs.get(id), micAlg.getMicAlg());
        }
    }
}
