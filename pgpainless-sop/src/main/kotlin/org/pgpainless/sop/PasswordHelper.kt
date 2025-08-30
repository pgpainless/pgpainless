// SPDX-FileCopyrightText: 2025 Paul Schaub <info@pgpainless.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.sop

import org.pgpainless.decryption_verification.ConsumerOptions
import org.pgpainless.util.Passphrase
import sop.exception.SOPGPException
import sop.util.UTF8Util

class PasswordHelper {
    companion object {

        /**
         * Add the given [password] as a message passphrase to the given [consumerOptions] instance.
         * If the [password] contains trailing or leading whitespace, additionally add the
         * [password] with these whitespace characters removed.
         *
         * @param password password
         * @param consumerOptions consumer options for message decryption
         */
        @JvmStatic
        fun addMessagePassphrasePlusRemoveWhitespace(
            password: String,
            consumerOptions: ConsumerOptions
        ) {
            Passphrase.fromPassword(password).let {
                consumerOptions.addMessagePassphrase(it)
                val trimmed = it.withTrimmedWhitespace()
                if (!it.getChars().contentEquals(trimmed.getChars())) {
                    consumerOptions.addMessagePassphrase(trimmed)
                }
            }
        }

        /**
         * Add the given [password] to the given [protector] instance. If the [password] contains
         * trailing or leading whitespace, additionally add the [password] with these whitespace
         * characters removed.
         *
         * @param password password
         * @param protector secret key ring protector
         * @throws SOPGPException.PasswordNotHumanReadable if the password is not a valid UTF-8
         *   string representation.
         */
        @JvmStatic
        fun addPassphrasePlusRemoveWhitespace(
            password: ByteArray,
            protector: MatchMakingSecretKeyRingProtector
        ) {
            val string =
                try {
                    UTF8Util.decodeUTF8(password)
                } catch (e: CharacterCodingException) {
                    throw SOPGPException.PasswordNotHumanReadable(
                        "Cannot UTF8-decode password: ${e.stackTraceToString()}")
                }
            addPassphrasePlusRemoveWhitespace(string, protector)
        }

        /**
         * Add the given [password] to the given [protector] instance. If the [password] contains
         * trailing or leading whitespace, additionally add the [password] with these whitespace
         * characters removed.
         *
         * @param password password
         * @param protector secret key ring protector
         */
        @JvmStatic
        fun addPassphrasePlusRemoveWhitespace(
            password: String,
            protector: MatchMakingSecretKeyRingProtector
        ) {
            Passphrase.fromPassword(password).let {
                protector.addPassphrase(it)
                val trimmed = it.withTrimmedWhitespace()
                if (!it.getChars().contentEquals(trimmed.getChars())) {
                    protector.addPassphrase(trimmed)
                }
            }
        }
    }
}
