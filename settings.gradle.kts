pluginManagement { repositories { gradlePluginPortal(); google(); mavenCentral() } }
dependencyResolutionManagement { repositories { mavenCentral(); google() } }
rootProject.name = "uncrackable-l5"
include(":app", ":server", ":attestation-verifier")
project(":attestation-verifier").projectDir = file("third_party/android-keyattestation")
