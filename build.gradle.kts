plugins {
    kotlin("jvm") version "2.2.10" apply false
    kotlin("android") version "2.2.10" apply false
    kotlin("plugin.serialization") version "2.2.10" apply false
    id("com.android.application") version "9.3.2" apply false
}
allprojects {
    dependencyLocking { lockAllConfigurations() }
}
