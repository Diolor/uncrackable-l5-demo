plugins { kotlin("jvm"); kotlin("plugin.serialization"); application }
application { mainClass.set("org.owasp.uncrackable.server.MainKt") }
kotlin { jvmToolchain(21) }
dependencies {
    implementation("org.postgresql:postgresql:42.7.13")
    implementation("io.ktor:ktor-server-netty:3.2.3")
    implementation("com.google.cloud:google-cloud-firestore:3.45.0")
    runtimeOnly("org.slf4j:slf4j-simple:2.0.17")
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

// Include only reviewed recordings; fixtures/local may contain unrelated live captures.
sourceSets.test {
    resources.srcDir(rootProject.file("fixtures"))
    resources.include("oneplus9pro-android14-tee-tier2.json")
    resources.srcDir("roots")
    resources.include("google-attestation-roots.pem")
}

// Local integration launcher (test classpath only). See LocalMain.kt for environment variables.
tasks.register<JavaExec>("runLocal") {
    group = "application"
    description = "Runs the backend on loopback with an in-memory replay store for device integration."
    classpath = sourceSets.test.get().runtimeClasspath
    mainClass.set((findProperty("localMain") as String?) ?: "org.owasp.uncrackable.server.LocalMainKt")
    workingDir = rootProject.projectDir
}
