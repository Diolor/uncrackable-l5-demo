package org.owasp.mastg.uncrackable5

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertNull

class FlagRecordTest {
    private val iv = ByteArray(12) { it.toByte() }
    private val ct = ByteArray(40) { (it * 3).toByte() }

    @Test fun roundTrip() {
        val record = FlagRecord(FlagRecord.VERSION, 2, iv, ct)
        val decoded = FlagRecord.decode(record.encode())!!
        assertEquals(2, decoded.tier)
        assertContentEquals(iv, decoded.iv)
        assertContentEquals(ct, decoded.ciphertext)
        assertContentEquals(byteArrayOf(1, 2), decoded.aad())
    }

    @Test fun rejectsMalformed() {
        assertNull(FlagRecord.decode(ByteArray(0)))
        assertNull(FlagRecord.decode(byteArrayOf(2, 1, 12) + iv + ct))          // unknown version
        assertNull(FlagRecord.decode(byteArrayOf(1, 3, 12) + iv + ct))          // bad tier
        assertNull(FlagRecord.decode(byteArrayOf(1, 1, 12) + iv + ByteArray(16))) // tag only, no ciphertext
        assertNull(FlagRecord.decode(byteArrayOf(1, 1, 8) + ByteArray(8) + ct))  // short IV
        assertNull(FlagRecord.decode(ByteArray(FlagRecord.MAX_SIZE + 1)))
    }

    @Test fun tierIsBoundIntoAad() {
        val a = FlagRecord(1, 1, iv, ct).aad()
        val b = FlagRecord(1, 2, iv, ct).aad()
        assert(!a.contentEquals(b))
    }
}
