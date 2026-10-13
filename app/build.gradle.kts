plugins {
    id("com.android.application")
}

android {
    namespace = "com.example.cipher"
    compileSdk = 36

    defaultConfig {
        applicationId = "com.example.cipher"
        minSdk = 24
        targetSdk = 36
        versionCode = 1
        versionName = "1.0.0"
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    dependencies {
        androidTestImplementation("androidx.test:runner:1.7.0")
        androidTestImplementation("androidx.test.ext:junit:1.3.0")
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"))
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}
