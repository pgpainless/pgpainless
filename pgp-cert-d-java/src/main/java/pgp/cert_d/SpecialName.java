// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.cert_d;

import java.util.HashMap;
import java.util.Map;

/**
 * Enum of known special names.
 */
public enum SpecialName {
    /**
     * Certificate acting as trust root.
     * This certificate is used to delegate other trustworthy certificates and to bind pet names to certificates.
     */
    TRUST_ROOT("trust-root"),
    ;

    static Map<String, SpecialName> MAP = new HashMap<>();

    static {
        for (SpecialName specialName : values()) {
            MAP.put(specialName.getValue(), specialName);
        }
    }

    final String value;

    SpecialName(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }

    public static SpecialName fromString(String value) {
        return MAP.get(value);
    }
}
