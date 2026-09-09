plugins {
    kotlin("jvm") version "2.2.0" apply false
    kotlin("android") version "2.2.0" apply false
    kotlin("plugin.serialization") version "2.2.0" apply false
    id("com.android.application") version "8.13.2" apply false
}
allprojects {
    dependencyLocking { lockAllConfigurations() }
}
