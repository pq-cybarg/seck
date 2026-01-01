// Plan-17 Android share-target. Standard AGP project; the executor
// fills the rest of the gradle wrapper. Build via:
//   ./gradlew :seckshare:assembleRelease

plugins {
    id("com.android.application") version "8.4.0"
    id("org.jetbrains.kotlin.android") version "2.0.0"
}

android {
    namespace = "net.seck.share"
    compileSdk = 35
    defaultConfig {
        applicationId = "net.seck.share"
        minSdk = 30
        targetSdk = 35
        versionCode = 1
        versionName = "2.0.0"
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

dependencies {
    implementation("androidx.core:core-ktx:1.13.1")
    // boringtun via JNI (cloudflare/boringtun's Android publisher) is
    // wired by the executor.
}
