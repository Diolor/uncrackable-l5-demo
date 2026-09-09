package org.owasp.uncrackable.server

import com.android.keyattestation.verifier.*
import com.android.keyattestation.verifier.testing.FakeCalendar
import com.android.keyattestation.verifier.testing.KeyAttestationCertPathFactory
import com.google.protobuf.ByteString
import kotlinx.serialization.json.Json
import java.io.File
import java.math.BigInteger
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.util.Base64

/**
 * Generates a synthetic parity corpus (JSON lines of [ParityCase]) with Google's test certificate
 * factory, covering every chain shape and key-description variation the verifier distinguishes.
 * The expected verdicts are not recorded here; [ParityOracle] produces them.
 *
 * Run: ./gradlew :server:runLocal -PlocalMain=org.owasp.uncrackable.server.ParityCorpusKt
 * with PARITY_OUT set to the destination file.
 */
private const val PACKAGE = "org.owasp.mastg.uncrackable5"

fun main() {
    val output = File(System.getenv("PARITY_OUT") ?: error("PARITY_OUT required"))
    val json = Json { explicitNulls = false }
    val calendar = FakeCalendar()
    val factory = KeyAttestationCertPathFactory(calendar)
    val signer = ByteArray(32) { 4 }
    val signerHex = signer.joinToString("") { "%02x".format(it.toInt() and 255) }
    val leafKey = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
    val otherKey = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
    val challenge = ByteArray(57) { (it * 7).toByte() }.also { it[0] = 1 }
    val challengeText = Base64.getUrlEncoder().withoutPadding().encodeToString(challenge)
    val roots = pem(factory.root)
    val now = calendar.now().toString()
    val enc = Base64.getEncoder()

    fun appId(pkg: String = PACKAGE, signers: Set<ByteString> = setOf(ByteString.copyFrom(signer)), extraPackage: Boolean = false) =
        AttestationApplicationId(
            buildSet { add(AttestationPackageInfo(pkg, BigInteger.ONE)); if (extraPackage) add(AttestationPackageInfo("other.pkg", BigInteger.TWO)) },
            signers,
        )
    fun hw(locked: Boolean = true, state: VerifiedBootState = VerifiedBootState.VERIFIED, purposes: Set<BigInteger> = setOf(BigInteger.valueOf(2)),
           algorithms: BigInteger? = BigInteger.valueOf(3), keySize: BigInteger? = BigInteger.valueOf(256), ecCurve: BigInteger? = BigInteger.ONE,
           digests: Set<BigInteger>? = setOf(BigInteger.valueOf(4)), origin: Origin? = Origin.GENERATED, rootOfTrust: RootOfTrust? =
               RootOfTrust(ByteString.copyFrom(ByteArray(32)), locked, state)) =
        AuthorizationList(purposes = purposes, algorithms = algorithms, keySize = keySize, ecCurve = ecCurve, digests = digests,
            origin = origin, rootOfTrust = rootOfTrust, osVersion = BigInteger.valueOf(140000), osPatchLevel = PatchLevel.from("202409"),
            attestationIdBrand = "OnePlus")
    fun desc(level: SecurityLevel = SecurityLevel.TRUSTED_ENVIRONMENT, keyMint: SecurityLevel = level,
             sw: AuthorizationList = AuthorizationList(attestationApplicationId = appId(), creationDateTime = BigInteger.valueOf(1700000000000)),
             hw: AuthorizationList = hw(), ch: ByteArray = challenge) =
        KeyDescription(BigInteger.valueOf(300), level, BigInteger.valueOf(300), keyMint, ByteString.copyFrom(ch), ByteString.EMPTY, sw, hw)

    val cases = ArrayList<ParityCase>()
    fun emit(id: String, d: KeyDescription, remote: Boolean = false, key: java.security.KeyPair = leafKey, popKey: java.security.KeyPair = key,
             popData: ByteArray = challenge, chainEdit: (List<X509Certificate>) -> List<String> = { c -> c.map { enc.encodeToString(it.encoded) } },
             pkg: String = PACKAGE, serials: List<String> = emptyList(), at: String = now, rootsPem: String = roots) {
        val chain = factory.generateCertPath(d, remotelyProvisioned = remote, leafKey = key.public).certificatesWithAnchor
        val pop = Signature.getInstance("SHA256withECDSA").run { initSign(popKey.private); update(popData); sign() }
        cases += ParityCase(id, AttestRequest(challengeText, chainEdit(chain), enc.encodeToString(pop)), at, pkg, signerHex, rootsPem, serials)
    }

    emit("baseline-tee", desc())
    emit("baseline-strongbox", desc(SecurityLevel.STRONG_BOX))
    emit("baseline-rkp", desc(), remote = true)
    emit("rkp-strongbox", desc(SecurityLevel.STRONG_BOX), remote = true)
    emit("software-levels", desc(SecurityLevel.SOFTWARE))
    emit("mismatched-levels", desc(SecurityLevel.TRUSTED_ENVIRONMENT, SecurityLevel.STRONG_BOX))
    emit("strongbox-claim-on-tee-chain", desc(hw = hw()).copy(keyMintSecurityLevel = SecurityLevel.STRONG_BOX, attestationSecurityLevel = SecurityLevel.STRONG_BOX),
        chainEdit = { c -> factory.generateCertPath(desc(), leafKey = leafKey.public).certificatesWithAnchor.let { _ -> c.map { enc.encodeToString(it.encoded) } } })
    for (locked in listOf(true, false)) for (state in VerifiedBootState.entries) {
        emit("boot-locked=$locked-$state", desc(hw = hw(locked = locked, state = state)))
    }
    emit("no-root-of-trust", desc(hw = hw(rootOfTrust = null)))
    emit("sw-root-of-trust-only", desc(sw = AuthorizationList(attestationApplicationId = appId(), rootOfTrust = RootOfTrust(ByteString.copyFrom(ByteArray(32)), true, VerifiedBootState.VERIFIED)), hw = hw(rootOfTrust = null)))
    emit("origin-imported", desc(hw = hw(origin = Origin.IMPORTED)))
    emit("origin-missing", desc(hw = hw(origin = null)))
    emit("wrong-package", desc(sw = AuthorizationList(attestationApplicationId = appId(pkg = "org.owasp.mastg.uncrackable5.debug"))))
    emit("extra-package", desc(sw = AuthorizationList(attestationApplicationId = appId(extraPackage = true))))
    emit("wrong-signer", desc(sw = AuthorizationList(attestationApplicationId = appId(signers = setOf(ByteString.copyFrom(ByteArray(32)))))))
    emit("extra-signer", desc(sw = AuthorizationList(attestationApplicationId = appId(signers = setOf(ByteString.copyFrom(signer), ByteString.copyFrom(ByteArray(32)))))))
    emit("no-signers", desc(sw = AuthorizationList(attestationApplicationId = appId(signers = emptySet()))))
    emit("no-app-id", desc(sw = AuthorizationList()))
    emit("app-id-in-hw-only", desc(sw = AuthorizationList(), hw = hw().copy(attestationApplicationId = appId())))
    emit("purpose-sign-and-verify", desc(hw = hw(purposes = setOf(BigInteger.valueOf(2), BigInteger.valueOf(3)))))
    emit("purpose-verify", desc(hw = hw(purposes = setOf(BigInteger.valueOf(3)))))
    emit("algorithm-rsa", desc(hw = hw(algorithms = BigInteger.ONE)))
    emit("keysize-384", desc(hw = hw(keySize = BigInteger.valueOf(384))))
    emit("curve-p384", desc(hw = hw(ecCurve = BigInteger.valueOf(2))))
    emit("digest-sha512", desc(hw = hw(digests = setOf(BigInteger.valueOf(6)))))
    emit("digests-two", desc(hw = hw(digests = setOf(BigInteger.valueOf(4), BigInteger.valueOf(6)))))
    emit("digests-missing", desc(hw = hw(digests = null)))
    emit("wrong-challenge", desc(ch = ByteArray(57) { 9 }))
    emit("empty-challenge", desc(ch = ByteArray(0)))
    emit("pop-wrong-key", desc(), popKey = otherKey)
    emit("pop-wrong-data", desc(), popData = ByteArray(57) { 9 })
    fun withPop(id: String, pop: String) {
        emit(id, desc())
        val last = cases.removeAt(cases.lastIndex)
        cases += ParityCase(last.id, AttestRequest(last.request.challenge, last.request.chain, pop), last.now, last.packageName, last.signer, last.roots, last.serials)
    }
    withPop("pop-garbage", "AAAA")
    withPop("pop-empty", "")
    withPop("pop-not-base64", "not base64!")
    withPop("pop-too-long", "A".repeat(129))
    withPop("pop-url-safe", "MEUCIQD-_w")
    emit("chain-without-root", desc(), chainEdit = { c -> c.dropLast(1).map { enc.encodeToString(it.encoded) } })
    emit("chain-without-root-rkp", desc(), remote = true, chainEdit = { c -> c.dropLast(1).map { enc.encodeToString(it.encoded) } })
    emit("chain-leaf-only", desc(), chainEdit = { c -> c.take(1).map { enc.encodeToString(it.encoded) } })
    emit("chain-leaf-and-root", desc(), chainEdit = { c -> listOf(c.first(), c.last()).map { enc.encodeToString(it.encoded) } })
    emit("chain-reversed", desc(), chainEdit = { c -> c.reversed().map { enc.encodeToString(it.encoded) } })
    emit("chain-dropped-intermediate", desc(), chainEdit = { c -> (c.take(2) + c.last()).map { enc.encodeToString(it.encoded) } })
    emit("chain-duplicate-leaf", desc(), chainEdit = { c -> (listOf(c.first()) + c).map { enc.encodeToString(it.encoded) } })
    emit("chain-leaf-appended", desc(), chainEdit = { c -> (c + c.first()).map { enc.encodeToString(it.encoded) } })
    emit("chain-root-twice", desc(), chainEdit = { c -> (c + c.last()).map { enc.encodeToString(it.encoded) } })
    emit("chain-pem-wrapped", desc(), chainEdit = { c -> c.map { "-----BEGIN CERTIFICATE-----\n" + enc.encodeToString(it.encoded) + "\n-----END CERTIFICATE-----" } })
    emit("chain-trailing-byte", desc(), chainEdit = { c -> c.mapIndexed { i, x -> enc.encodeToString(if (i == 0) x.encoded + byteArrayOf(0) else x.encoded) } })
    emit("chain-truncated-leaf", desc(), chainEdit = { c -> c.mapIndexed { i, x -> enc.encodeToString(if (i == 0) x.encoded.copyOf(x.encoded.size - 1) else x.encoded) } })
    emit("chain-flipped-signature-bit", desc(), chainEdit = { c -> c.mapIndexed { i, x -> enc.encodeToString(if (i == 0) x.encoded.copyOf().also { b -> b[b.lastIndex] = (b.last().toInt() xor 1).toByte() } else x.encoded) } })
    emit("chain-url-safe-base64", desc(), chainEdit = { c -> c.map { Base64.getUrlEncoder().encodeToString(it.encoded) } })
    emit("chain-unpadded-base64", desc(), chainEdit = { c -> c.map { Base64.getEncoder().withoutPadding().encodeToString(it.encoded) } })
    emit("chain-whitespace-base64", desc(), chainEdit = { c -> c.map { enc.encodeToString(it.encoded).chunked(64).joinToString("\n") } })
    emit("chain-empty-entry", desc(), chainEdit = { c -> c.map { enc.encodeToString(it.encoded) } + "" })
    emit("expired-now", desc(), at = calendar.today.plusDays(8).atStartOfDay(java.time.ZoneOffset.UTC).toInstant().toString())
    emit("expired-now-rkp", desc(), remote = true, at = calendar.today.plusDays(8).atStartOfDay(java.time.ZoneOffset.UTC).toInstant().toString())
    emit("not-yet-valid", desc(), at = calendar.today.minusDays(8).atStartOfDay(java.time.ZoneOffset.UTC).toInstant().toString())
    emit("leaf-expiry-boundary", desc(), at = calendar.today.plusDays(7).atStartOfDay(java.time.ZoneOffset.UTC).toInstant().toString())
    emit("leaf-expiry-boundary-plus-1s", desc(), at = calendar.today.plusDays(7).atStartOfDay(java.time.ZoneOffset.UTC).toInstant().plusSeconds(1).toString())
    emit("revoked-root", desc(), serials = listOf(factory.root.serialNumber.toString(16)))
    emit("revoked-leaf", desc(), serials = listOf("1"))
    emit("revoked-intermediate", desc(), serials = listOf(BigInteger.valueOf(0x1234567890).toString(16)))
    emit("revoked-attestation-cert", desc(), serials = listOf(BigInteger.valueOf(0xcafbad).toString(16)))
    emit("revoked-unrelated", desc(), serials = listOf("deadbeef"))
    val otherRoot = KeyAttestationCertPathFactory(calendar, hardcodedRootKey = otherKey).root
    emit("untrusted-root", desc(), rootsPem = pem(otherRoot))
    emit("two-roots-configured", desc(), rootsPem = pem(otherRoot) + "\n" + roots)
    emit("wrong-package-config", desc(), pkg = "org.owasp.mastg.uncrackable5.debug")

    output.bufferedWriter().use { w -> cases.forEach { w.write(json.encodeToString(ParityCase.serializer(), it)); w.newLine() } }
    println("wrote ${cases.size} cases to $output")
}

private fun pem(cert: X509Certificate) =
    "-----BEGIN CERTIFICATE-----\n" + Base64.getMimeEncoder(64, "\n".toByteArray()).encodeToString(cert.encoded) + "\n-----END CERTIFICATE-----"
