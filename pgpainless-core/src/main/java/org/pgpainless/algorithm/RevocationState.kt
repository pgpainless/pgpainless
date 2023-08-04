// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.algorithm

import org.pgpainless.util.DateUtil
import java.lang.AssertionError
import java.util.*
import kotlin.NoSuchElementException

class RevocationState private constructor(
        val type: RevocationStateType,
        private val _date: Date?): Comparable<RevocationState> {

    val date: Date
        get() {
            if (!isSoftRevocation()) {
                throw NoSuchElementException("RevocationStateType is not equal to 'softRevoked'. Cannot extract date.")
            }
            return _date!!
        }

    private constructor(type: RevocationStateType): this(type, null)

    fun isSoftRevocation() = type == RevocationStateType.softRevoked
    fun isHardRevocation() = type == RevocationStateType.hardRevoked
    fun isNotRevoked() = type == RevocationStateType.notRevoked

    companion object {
        @JvmStatic
        fun notRevoked() = RevocationState(RevocationStateType.notRevoked)

        @JvmStatic
        fun softRevoked(date: Date) = RevocationState(RevocationStateType.softRevoked, date)

        @JvmStatic
        fun hardRevoked() = RevocationState(RevocationStateType.hardRevoked)
    }

    override fun compareTo(other: RevocationState): Int {
        return when(type) {
            RevocationStateType.notRevoked ->
                if (other.isNotRevoked()) 0
                else -1
            RevocationStateType.softRevoked ->
                if (other.isNotRevoked()) 1
                // Compare soft dates in reverse
                else if (other.isSoftRevocation()) other.date.compareTo(date)
                else -1
            RevocationStateType.hardRevoked ->
                if (other.isHardRevocation()) 0
                else 1
            else -> throw AssertionError("Unknown type: $type")
        }
    }

    override fun toString(): String {
        return buildString {
            append(type)
            if (isSoftRevocation()) append(" (${DateUtil.formatUTCDate(date)})")
        }
    }

    override fun hashCode(): Int {
        return type.hashCode() * 31 + if (isSoftRevocation()) date.hashCode() else 0
    }

    override fun equals(other: Any?): Boolean {
        if (other == null) {
            return false
        }
        if (this === other) {
            return true
        }
        if (other !is RevocationState) {
            return false
        }
        if (type != other.type) {
            return false
        }
        if (isSoftRevocation()) {
            return DateUtil.toSecondsPrecision(date).time == DateUtil.toSecondsPrecision(other.date).time
        }
        return true
    }
}