plugins { kotlin("jvm"); `java-library`; `java-test-fixtures` }
kotlin { jvmToolchain(21) }
sourceSets {
    main { kotlin.exclude("VerifierCli.kt") }
    testFixtures { kotlin.srcDir("src/testFixtures") }
}
dependencies {
    implementation("androidx.annotation:annotation:1.9.1")
    implementation("co.nstant.in:cbor:0.9")
    implementation("com.google.code.gson:gson:2.11.0")
    implementation("com.google.errorprone:error_prone_annotations:2.41.0")
    api("com.google.protobuf:protobuf-javalite:4.28.3")
    implementation("com.google.protobuf:protobuf-kotlin-lite:4.28.3")
    implementation("org.bouncycastle:bcpkix-jdk18on:1.78.1")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.10.2")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-guava:1.10.2")
    api("com.google.guava:guava:33.5.0-jre")
    testFixturesImplementation("org.bouncycastle:bcpkix-jdk18on:1.78.1")
    testFixturesImplementation("com.google.protobuf:protobuf-kotlin-lite:4.28.3")
    testFixturesImplementation("com.google.code.gson:gson:2.11.0")
    testFixturesImplementation("com.google.errorprone:error_prone_annotations:2.41.0")
}
