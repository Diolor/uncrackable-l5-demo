pluginManagement { repositories { gradlePluginPortal(); google(); mavenCentral() } }
plugins {
	id("org.gradle.toolchains.foojay-resolver-convention") version "1.0.0"
}
dependencyResolutionManagement { repositories { mavenCentral(); google() } }
rootProject.name = "uncrackable-l5"
include(":server", ":attestation-verifier")
if (!providers.gradleProperty("serverOnly").isPresent) {
    include(":app")
    project(":app").projectDir = file("Mobile app")
}
project(":attestation-verifier").projectDir = file("third_party/android-keyattestation")
