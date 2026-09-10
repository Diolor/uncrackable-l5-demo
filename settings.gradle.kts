pluginManagement { repositories { gradlePluginPortal(); google(); mavenCentral() } }
plugins {
    id("org.gradle.toolchains.foojay-resolver-convention") version "1.0.0"
}
dependencyResolutionManagement { repositories { mavenCentral(); google() } }
rootProject.name = "uncrackable-l5"
include(":app")
