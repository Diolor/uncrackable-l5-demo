package org.owasp.mastg.uncrackable5

import okhttp3.CertificatePinner

/**
 * SPKI SHA-256 pins for the six public roots the backend may chain to. Roots only, OR-ed.
 *
 * Each value is computed from the CA's own published PEM (kept in `Mobile app/pins/`), never from
 * a live connection:
 *   openssl x509 -in <root>.pem -pubkey -noout | openssl pkey -pubin -outform der \
 *     | openssl dgst -sha256 -binary | base64
 *
 * OkHttp's CertificatePinner runs after platform path validation and matches any certificate
 * in the *verified* chain, so pinning a root actually works. There is no refresh policy: the
 * APK is immutable, and a pin change means a new APK.
 */
object Pins {

    val ROOT_SPKI_SHA256: List<String> = listOf(
        "sha256/hxqRlPTu1bMS/0DITB1SSu0vd4u/8l8TjPgfaAp63Gc=", // GTS Root R1 (exp. 2036-06-22)
        "sha256/Vfd95BwDeSQo+NUYxVEEIlvkOlWY2SalKK1lPhzOx78=", // GTS Root R2 (exp. 2036-06-22)
        "sha256/QXnt2YHvdHR3tJYmQIr0Paosp6t/nggsEGD4QJZ3Q0g=", // GTS Root R3 (exp. 2036-06-22)
        "sha256/mEflZT5enoR1FuXLgYYGqnVEoZvmf9c2bVBpiOjYQ0c=", // GTS Root R4 (exp. 2036-06-22)
        "sha256/C5+lpZ7tcVwmwQIMcRtPbsQtWLABXhQzejna0wHFr8M=", // ISRG Root X1 (exp. 2035-06-04)
        "sha256/diGVwiVYbubAI3RW4hB9xU8e/CH2GnkuvVFZE8zmgzI=", // ISRG Root X2 (exp. 2040-09-17)
    )

    fun pinner(host: String): CertificatePinner =
        CertificatePinner.Builder().add(host, *ROOT_SPKI_SHA256.toTypedArray()).build()
}
