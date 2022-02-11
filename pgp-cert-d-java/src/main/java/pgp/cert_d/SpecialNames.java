// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.cert_d;

import java.util.HashMap;
import java.util.Map;

public class SpecialNames {

    private static final Map<String, String> SPECIAL_NAMES = new HashMap<>();

    static {
        SPECIAL_NAMES.put("TRUST-ROOT", "trust-root"); // TODO: Remove
        SPECIAL_NAMES.put("trust-root", "trust-root");
    }

    public static String lookupSpecialName(String specialName) {
        return SPECIAL_NAMES.get(specialName);
    }
}
