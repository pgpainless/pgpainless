// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.util

import org.bouncycastle.util.Arrays

/**
 * Passphrase for keys or messages.
 *
 * @param chars may be null for empty passwords.
 */
class Passphrase(chars: CharArray?) {
    private val lock = Any()
    private var valid = true
    private val chars: CharArray?

    init {
        this.chars = trimWhitespace(chars)
    }

    /**
     * Return a copy of the underlying char array. A return value of null represents an empty
     * password.
     *
     * @return passphrase chars.
     * @throws IllegalStateException in case the password has been cleared at this point.
     */
    fun getChars(): CharArray? =
        synchronized(lock) {
            check(valid) { "Passphrase has been cleared." }
            chars?.copyOf()
        }

    /**
     * Return true if the passphrase has not yet been cleared.
     *
     * @return valid
     */
    val isValid: Boolean
        get() = synchronized(lock) { valid }

    /**
     * Return true if the passphrase represents no password.
     *
     * @return empty
     */
    val isEmpty: Boolean
        get() = synchronized(lock) { valid && chars == null }

    /** Overwrite the char array with spaces and mark the [Passphrase] as invalidated. */
    fun clear() =
        synchronized(lock) {
            chars?.fill(' ')
            valid = false
        }

    override fun equals(other: Any?): Boolean {
        return if (other == null) false
        else if (this === other) true
        else if (other !is Passphrase) false
        else
            getChars() == null && other.getChars() == null ||
                Arrays.constantTimeAreEqual(getChars(), other.getChars())
    }

    override fun hashCode(): Int = getChars()?.let { String(it) }.hashCode()

    companion object {

        /**
         * Create a [Passphrase] from a [CharSequence].
         *
         * @param password password
         * @return passphrase
         */
        @JvmStatic
        fun fromPassword(password: CharSequence) = Passphrase(password.toString().toCharArray())

        @JvmStatic fun emptyPassphrase() = Passphrase(null)

        /**
         * Return a copy of the passed in char array, with leading and trailing whitespace
         * characters removed. If the passed in char array is null, return null. If the resulting
         * char array is empty, return null as well.
         *
         * @param chars char array
         * @return copy of char array with leading and trailing whitespace characters removed
         */
        @JvmStatic
        private fun trimWhitespace(chars: CharArray?): CharArray? {
            return chars
                ?.dropWhile { it.isWhitespace() }
                ?.dropLastWhile { it.isWhitespace() }
                ?.toCharArray()
                ?.let { if (it.isEmpty()) null else it }
        }
    }
}
