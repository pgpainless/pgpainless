// SPDX-FileCopyrightText: 2026 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package openpgp

import java.util.function.Predicate

fun <T> Collection<T>.anyOrElse(
    predicate: Predicate<T>,
    block: (Collection<T>) -> Boolean
): Boolean {
    return this.any { predicate.test(it) }.orElse { block.invoke(this) }
}
