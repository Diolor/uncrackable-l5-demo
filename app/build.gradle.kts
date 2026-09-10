plugins {
    id("com.android.application")
    kotlin("android")
    kotlin("plugin.serialization")
}

// Release builds always use the HTTPS origin; debug builds may point at a local server.
val releaseBaseUrl = (findProperty("crackmeReleaseBaseUrl") as String?) ?: "https://crackme.lorentzos.com"
val baseUrl = (findProperty("crackmeBaseUrl") as String?) ?: releaseBaseUrl
require(Regex("https://[A-Za-z0-9.-]+(?::[0-9]+)?").matches(releaseBaseUrl)) {
    "Release URL must be an HTTPS origin without a path, credentials, query or fragment"
}

android {
    namespace = "org.owasp.mastg.uncrackable5"
    compileSdk = 36

    defaultConfig {
        applicationId = "org.owasp.mastg.uncrackable5"
        minSdk = 28
        targetSdk = 36
        versionCode = 1
        versionName = "1.0"
        resourceConfigurations += listOf("en")
    }

    signingConfigs {
        create("release") {
            val path = System.getenv("UNCRACKABLE_KEYSTORE")
            if (path != null) {
                storeFile = file(path)
                storePassword = System.getenv("UNCRACKABLE_KEYSTORE_PASSWORD")
                keyAlias = System.getenv("UNCRACKABLE_KEY_ALIAS") ?: "uncrackable-l5"
                keyPassword = System.getenv("UNCRACKABLE_KEY_PASSWORD")
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            isDebuggable = false
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
            buildConfigField("String", "BASE_URL", "\"$releaseBaseUrl\"")
            if (System.getenv("UNCRACKABLE_KEYSTORE") != null) signingConfig = signingConfigs.getByName("release")
        }
        debug {
            applicationIdSuffix = ".debug"
            buildConfigField("String", "BASE_URL", "\"$baseUrl\"")
        }
    }

    buildFeatures { buildConfig = true }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }
    dependenciesInfo {
        includeInApk = false
        includeInBundle = false
    }
    packaging {
        resources.excludes += listOf("META-INF/*.version", "META-INF/*.kotlin_module", "kotlin/**", "DebugProbesKt.bin", "kotlin-tooling-metadata.json")
    }
    lint { abortOnError = false }
}

dependencies {
    implementation("com.squareup.okhttp3:okhttp-jvm:5.5.0")
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.11.0")
    testImplementation(kotlin("test-junit"))
    testImplementation("junit:junit:4.13.2")
}
