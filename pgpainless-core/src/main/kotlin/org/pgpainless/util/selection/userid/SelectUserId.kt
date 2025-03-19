// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.util.selection.userid

import java.util.function.Predicate
import org.bouncycastle.openpgp.PGPKeyRing
import org.bouncycastle.openpgp.api.OpenPGPCertificate
import org.pgpainless.PGPainless

abstract class SelectUserId : Predicate<String>, (String) -> Boolean {

    /** Legacy glue code to forward accept() calls to invoke() instead. */
    @Deprecated("Use invoke() instead.", ReplaceWith("invoke(userId)"))
    protected fun accept(userId: String): Boolean = invoke(userId)

    override fun test(userId: String): Boolean = invoke(userId)

    companion object {

        /**
         * Filter for user-ids which match the given [query] exactly.
         *
         * @param query query
         * @return filter
         */
        @JvmStatic
        fun exactMatch(query: CharSequence) =
            object : SelectUserId() {
                override fun invoke(userId: String): Boolean = userId == query
            }

        /**
         * Filter for user-ids which start with the given [substring].
         *
         * @param substring substring
         * @return filter
         */
        @JvmStatic
        fun startsWith(substring: CharSequence) =
            object : SelectUserId() {
                override fun invoke(userId: String): Boolean = userId.startsWith(substring)
            }

        /**
         * Filter for user-ids which contain the given [substring].
         *
         * @param substring query
         * @return filter
         */
        @JvmStatic
        fun containsSubstring(substring: CharSequence) =
            object : SelectUserId() {
                override fun invoke(userId: String): Boolean = userId.contains(substring)
            }

        /**
         * Filter for user-ids which contain the given [email] address. Note: This only accepts
         * user-ids which properly have the email address surrounded by angle brackets.
         *
         * The argument [email] can both be a plain email address (`foo@bar.baz`), or surrounded by
         * angle brackets (`<foo@bar.baz>`), the result of the filter will be the same.
         *
         * @param email email address
         * @return filter
         */
        @JvmStatic
        fun containsEmailAddress(email: CharSequence) =
            if (email.startsWith('<') && email.endsWith('>')) containsSubstring(email)
            else containsSubstring("<$email>")

        @JvmStatic
        fun byEmail(email: CharSequence) = or(exactMatch(email), containsEmailAddress(email))

        @JvmStatic
        fun validUserId(key: OpenPGPCertificate) =
            object : SelectUserId() {
                private val info = PGPainless.getInstance().inspect(key)

                override fun invoke(userId: String): Boolean = info.isUserIdValid(userId)
            }

        @JvmStatic
        fun validUserId(keyRing: PGPKeyRing) =
            object : SelectUserId() {
                private val info = PGPainless.inspectKeyRing(keyRing)

                override fun invoke(userId: String): Boolean = info.isUserIdValid(userId)
            }

        @JvmStatic
        fun and(vararg filters: SelectUserId) =
            object : SelectUserId() {
                override fun invoke(userId: String): Boolean = filters.all { it.invoke(userId) }
            }

        @JvmStatic
        fun or(vararg filters: SelectUserId) =
            object : SelectUserId() {
                override fun invoke(userId: String): Boolean = filters.any { it.invoke(userId) }
            }

        @JvmStatic
        fun not(filter: SelectUserId) =
            object : SelectUserId() {
                override fun invoke(userId: String): Boolean = !filter.invoke(userId)
            }
    }
}
