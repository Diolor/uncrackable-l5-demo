plugins { kotlin("jvm"); kotlin("plugin.serialization") }
kotlin { jvmToolchain(21) }
dependencies {
    implementation(project(":attestation-verifier"))
    implementation("io.ktor:ktor-server-core:3.2.3")
    implementation("io.ktor:ktor-server-content-negotiation:3.2.3")
    implementation("io.ktor:ktor-server-status-pages:3.2.3")
    implementation("io.ktor:ktor-serialization-kotlinx-json:3.2.3")
    testImplementation(kotlin("test-junit5"))
    testImplementation("io.ktor:ktor-server-test-host:3.2.3")
    testImplementation(testFixtures(project(":attestation-verifier")))
    testRuntimeOnly("org.junit.platform:junit-platform-launcher:1.12.2")
}
tasks.test { useJUnitPlatform() }
