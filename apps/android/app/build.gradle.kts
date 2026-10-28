plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}

android {
    namespace = "app.openpass"
    compileSdk = 35
    // Default API base URL baked into BuildConfig. Override at build time with
    // -Popenpass.apiUrl=... or the OPENPASS_API_URL env var (see .env.example).
    // Default is the emulator's host-loopback address for local API development.
    val apiUrl = (project.findProperty("openpass.apiUrl") as String?)
        ?: System.getenv("OPENPASS_API_URL")
        ?: "http://10.0.2.2:8787"
    defaultConfig {
        applicationId = "app.openpass"
        minSdk = 29        // Android 10
        targetSdk = 35
        versionCode = 1
        versionName = "0.1.0"
        buildConfigField("String", "OPENPASS_API_URL", "\"$apiUrl\"")
    }
    buildFeatures { compose = true; buildConfig = true }
    compileOptions { sourceCompatibility = JavaVersion.VERSION_17; targetCompatibility = JavaVersion.VERSION_17 }
    kotlinOptions { jvmTarget = "17" }
}

dependencies {
    implementation("androidx.compose.ui:ui:1.7.5")
    implementation("androidx.compose.material3:material3:1.3.1")
    implementation("androidx.activity:activity-compose:1.9.3")
    implementation("androidx.biometric:biometric:1.1.0")
    // Provider classes (CredentialProviderService etc.) ship inside the credentials artifact;
    // there is no separate credentials-provider artifact on Google Maven (verified).
    implementation("androidx.credentials:credentials:1.5.0")
    // UniFFI-generated bindings call the Rust core through JNA.
    implementation("net.java.dev.jna:jna:5.14.0@aar")
    // TODO: package libopenpass_core.so per ABI into jniLibs (cargo NDK build, scripts/build-android-core.sh)
}
