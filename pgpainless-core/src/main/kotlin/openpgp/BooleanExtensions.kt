// SPDX-FileCopyrightText: 2026 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package openpgp

fun Boolean.orElse(f: Function0<Boolean>): Boolean {
    return if (this) {
        true
    } else {
        f.invoke()
    }
}
