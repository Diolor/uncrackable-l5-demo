package org.owasp.mastg.uncrackable5

import java.util.Base64
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertFailsWith

class ChallengeTest {
    private val canonical = ByteArray(57) { it.toByte() }.also { it[0] = 1; it[10] = 0xff.toByte(); it[11] = 0xfb.toByte() }
    private val encoded = Base64.getUrlEncoder().withoutPadding().encodeToString(canonical)

    @Test fun decodesCanonicalChallenge() {
        assertContentEquals(canonical, Challenge.decode(encoded))
    }

    @Test fun rejectsNonCanonical() {
        assertFailsWith<IllegalArgumentException> { Challenge.decode(encoded + "=") }
        assertFailsWith<IllegalArgumentException> { Challenge.decode(encoded.dropLast(1)) }
        assertFailsWith<IllegalArgumentException> { Challenge.decode(encoded.replace('-', '+').replace('_', '/')) }
        val v2 = canonical.copyOf().also { it[0] = 2 }
        assertFailsWith<IllegalArgumentException> { Challenge.decode(Base64.getUrlEncoder().withoutPadding().encodeToString(v2)) }
    }
}
