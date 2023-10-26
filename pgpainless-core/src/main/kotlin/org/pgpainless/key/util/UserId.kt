// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.util

class UserId internal constructor(name: String?, comment: String?, email: String?) : CharSequence {

    private val _name: String?
    val comment: String?
    val email: String?

    init {
        this._name = name?.trim()
        this.comment = comment?.trim()
        this.email = email?.trim()
    }

    val full: String = buildString {
        if (name?.isNotBlank() == true) {
            append(getName(true))
        }
        if (comment?.isNotBlank() == true) {
            if (isNotEmpty()) {
                append(' ')
            }
            append("($comment)")
        }
        if (email?.isNotBlank() == true) {
            if (isNotEmpty()) {
                append(' ')
            }
            append("<$email>")
        }
    }

    override val length: Int
        get() = full.length

    val name: String?
        get() = getName(false)

    fun getName(preserveQuotes: Boolean): String? {
        return if (preserveQuotes || _name.isNullOrBlank()) {
            _name
        } else _name.removeSurrounding("\"")
    }

    override fun equals(other: Any?): Boolean {
        if (other === null) {
            return false
        }
        if (this === other) {
            return true
        }
        if (other !is UserId) {
            return false
        }
        return isComponentEqual(_name, other._name, false) &&
            isComponentEqual(comment, other.comment, false) &&
            isComponentEqual(email, other.email, true)
    }

    override fun get(index: Int): Char {
        return full[index]
    }

    override fun hashCode(): Int {
        return toString().hashCode()
    }

    override fun subSequence(startIndex: Int, endIndex: Int): CharSequence {
        return full.subSequence(startIndex, endIndex)
    }

    override fun toString(): String {
        return full
    }

    private fun isComponentEqual(
        value: String?,
        otherValue: String?,
        ignoreCase: Boolean
    ): Boolean = value.equals(otherValue, ignoreCase)

    fun toBuilder() =
        builder().also { builder ->
            if (this._name != null) builder.withName(_name)
            if (this.comment != null) builder.withComment(comment)
            if (this.email != null) builder.withEmail(email)
        }

    companion object {

        // Email regex: https://emailregex.com/
        // switched "a-z0-9" to "\p{L}\u0900-\u097F0-9" for better support for international
        // characters
        // \\p{L} = Unicode Letters
        // \u0900-\u097F = Hindi Letters
        @JvmStatic
        private val emailPattern =
            ("(?:[\\p{L}\\u0900-\\u097F0-9!#\\$%&'*+/=?^_`{|}~-]+(?:\\.[\\p{L}\\u0900-\\u097F0-9!#\\$%&'*+/=?^_`{|}~-]+)*|\"(?:[\\x01-\\x08\\x0b\\x0c\\x0e-" +
                    "\\x1f\\x21\\x23-\\x5b\\x5d-\\x7f]|\\\\[\\x01-\\x09\\x0b\\x0c\\x0e-\\x7f])*\")@(?:(?:[\\p{L}\\u0900-\\u097F0-9](?:[\\p{L}\\u0900-\\u097F0-9" +
                    "-]*[\\p{L}\\u0900-\\u097F0-9])?\\.)+[\\p{L}\\u0900-\\u097F0-9](?:[\\p{L}\\u0900-\\u097F0-9-]*[\\p{L}\\u0900-\\u097F0-9])?|\\[(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)" +
                    "\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?|[$\\p{L}\\u0900-\\u097F0-9-]*[\\p{L}\\u0900-\\u097F0-9]:(?:[\\x01-\\x08\\x0b\\x0c\\x0e-\\x1f" +
                    "\\x21-\\x5a\\x53-\\x7f]|\\\\[\\x01-\\x09\\x0b\\x0c\\x0e-\\x7f])+)])")
                .toPattern()

        // User-ID Regex
        // "Firstname Lastname (Comment) <email@example.com>"
        // All groups are optional
        // https://www.rfc-editor.org/rfc/rfc5322#page-16
        @JvmStatic
        private val nameAddrPattern =
            "^((?<name>.+?)\\s)?(\\((?<comment>.+?)\\)\\s)?(<(?<email>.+?)>)?$".toPattern()

        /**
         * Parse a [UserId] from free-form text, <pre>name-addr</pre> or <pre>mailbox</pre> string
         * and split it up into its components. Example inputs for this method:
         * <ul>
         * <li><pre>john@pgpainless.org</pre></li>
         * <li><pre>&lt;john@pgpainless.org&gt;</pre></li>
         * <li><pre>John Doe</pre></li>
         * <li><pre>John Doe &lt;john@pgpainless.org&gt;</pre></li>
         * <li><pre>John Doe (work email) &lt;john@pgpainless.org&gt;</pre></li>
         * </ul>
         *
         * In these cases, this method will detect email addresses, names and comments and expose
         * those via the respective getters. This method does not support parsing mail addresses of
         * the following formats:
         * <ul>
         * <li>Local domains without TLDs (<pre>user@localdomain1</pre>)</li>
         * <li><pre>" "@example.org</pre> (spaces between the quotes)</li>
         * <li><pre>"very.(),:;&lt;&gt;[]\".VERY.\"very@\\ \"very\".unusual"@strange.example.com</pre></li>
         * </ul>
         *
         * Note: This method does not guarantee that
         * <pre>string.equals(UserId.parse(string).toString())</pre> is true. For example,
         * <pre>UserId.parse("alice@pgpainless.org").toString()</pre> wraps the mail address in
         *
         * angled brackets.
         *
         * @param string user-id
         * @return parsed UserId object
         * @see <a href="https://www.rfc-editor.org/rfc/rfc5322#page-16">RFC5322 §3.4. Address
         *   Specification</a>
         */
        @JvmStatic
        fun parse(string: String): UserId {
            val trimmed = string.trim()
            nameAddrPattern.matcher(trimmed).let { nameAddrMatcher ->
                if (nameAddrMatcher.find()) {
                    val name = nameAddrMatcher.group(2)
                    val comment = nameAddrMatcher.group(4)
                    val mail = nameAddrMatcher.group(6)
                    require(emailPattern.matcher(mail).matches()) { "Malformed email address" }
                    return UserId(name, comment, mail)
                } else {
                    require(emailPattern.matcher(trimmed).matches()) { "Malformed email address" }
                    return UserId(null, null, trimmed)
                }
            }
        }

        @JvmStatic fun onlyEmail(email: String) = UserId(null, null, email)

        @JvmStatic fun nameAndEmail(name: String, email: String) = UserId(name, null, email)

        @JvmStatic
        fun compare(u1: UserId?, u2: UserId?, comparator: Comparator<UserId?>) =
            comparator.compare(u1, u2)

        @JvmStatic
        @Deprecated("Deprecated in favor of builde() method.", ReplaceWith("builder()"))
        fun newBuilder() = builder()

        @JvmStatic fun builder() = Builder()
    }

    class Builder internal constructor() {
        var name: String? = null
        var comment: String? = null
        var email: String? = null

        fun withName(name: String) = apply { this.name = name }

        fun withComment(comment: String) = apply { this.comment = comment }

        fun withEmail(email: String) = apply { this.email = email }

        fun noName() = apply { this.name = null }

        fun noComment() = apply { this.comment = null }

        fun noEmail() = apply { this.email = null }

        fun build() = UserId(name, comment, email)
    }

    class DefaultComparator : Comparator<UserId> {
        override fun compare(o1: UserId?, o2: UserId?): Int {
            return compareBy<UserId?> { it?._name }
                .thenBy { it?.comment }
                .thenBy { it?.email }
                .compare(o1, o2)
        }
    }

    class DefaultIgnoreCaseComparator : Comparator<UserId> {
        override fun compare(p0: UserId?, p1: UserId?): Int {
            return compareBy<UserId?> { it?._name?.lowercase() }
                .thenBy { it?.comment?.lowercase() }
                .thenBy { it?.email?.lowercase() }
                .compare(p0, p1)
        }
    }
}
