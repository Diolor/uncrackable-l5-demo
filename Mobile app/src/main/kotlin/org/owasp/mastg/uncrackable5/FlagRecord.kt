package org.owasp.mastg.uncrackable5

/**
 * On-disk layout of one encrypted flag record, independent of the platform so it can be unit tested:
 *
 *   version(1) || tier(1) || ivLength(1) || iv || ciphertext || gcmTag(16)
 *
 * The AAD bound into the GCM computation is `version || tier`, so a record cannot be moved between
 * tiers or reinterpreted under a different format version without failing authentication.
 */
class FlagRecord(val version: Int, val tier: Int, val iv: ByteArray, val ciphertext: ByteArray) {
    init {
        require(version in 1..255 && tier in 1..2 && iv.size in 12..255 && ciphertext.size > TAG_BYTES)
    }

    fun aad(): ByteArray = byteArrayOf(version.toByte(), tier.toByte())

    fun encode(): ByteArray = ByteArray(3 + iv.size + ciphertext.size).also {
        it[0] = version.toByte(); it[1] = tier.toByte(); it[2] = iv.size.toByte()
        iv.copyInto(it, 3)
        ciphertext.copyInto(it, 3 + iv.size)
    }

    companion object {
        const val VERSION = 1
        const val TAG_BYTES = 16
        const val MAX_SIZE = 4096

        /** Returns null for anything that is not a well-formed record; callers discard such files. */
        fun decode(bytes: ByteArray): FlagRecord? {
            if (bytes.size < 3 || bytes.size > MAX_SIZE) return null
            val version = bytes[0].toInt() and 0xff
            val tier = bytes[1].toInt() and 0xff
            val ivLength = bytes[2].toInt() and 0xff
            if (version != VERSION || tier !in 1..2 || ivLength < 12) return null
            if (bytes.size <= 3 + ivLength + TAG_BYTES) return null
            return FlagRecord(version, tier, bytes.copyOfRange(3, 3 + ivLength), bytes.copyOfRange(3 + ivLength, bytes.size))
        }
    }
}
