// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.cert_d.jdbc.sqlite;

import java.util.Comparator;

public class SpecialNameFingerprintComparator implements Comparator<String> {

    @Override
    public int compare(String t0, String t1) {
        boolean t0f = fastIsFingerprint(t0);
        boolean t1f = fastIsFingerprint(t1);

        return t0f ^ t1f ? // args are not of same "type", i.e. (fp, sn) / (sn, fp)
                (t0f ? 1 : -1) // fps are "larger"
                : t0.compareTo(t1); // else -> same arg type -> lexicographic comparison to not break sets
    }

    private boolean fastIsFingerprint(String fp) {
        // OpenPGP v4 fingerprint is 40 hex chars
        if (fp.length() != 40) {
            return false;
        }

        // c is hex
        for (char c : fp.toCharArray()) {
            // c < '0' || c > 'f'
            if (c < 48 || c > 102) {
                return false;
            }
            // c > '9' && c < 'a'
            if (c > 57 && c < 97) {
                return false;
            }
        }

        return true;
    }
}
