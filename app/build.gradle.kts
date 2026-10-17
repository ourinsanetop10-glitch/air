plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("com.google.devtools.ksp")
}

android {
    namespace = "com.airchat.mesh"
    compileSdk = 34

    defaultConfig {
        applicationId = "com.airchat.mesh"
        minSdk = 26
        targetSdk = 34
        versionCode = 1
        versionName = "0.1.0"
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
    }
}

dependencies {
    // AndroidX core + activity
    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.activity:activity-ktx:1.8.2")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.2")

    // Coroutines
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.8.1")

    // Room (offline-first local storage)
    implementation("androidx.room:room-runtime:2.6.1")
    implementation("androidx.room:room-ktx:2.6.1")
    ksp("androidx.room:room-compiler:2.6.1")

    // Cryptography: Ed25519 / X25519 subtle primitives
    implementation("com.google.crypto.tink:tink-android:1.13.0")
}
