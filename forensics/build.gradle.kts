plugins {
    alias(libs.plugins.android.library)
    alias(libs.plugins.kotlin.android)
}

android {
    namespace = "com.docintegrity.forensics"
    compileSdk = 36
    buildToolsVersion = "35.0.0"

    defaultConfig {
        minSdk = 26
        consumerProguardFiles("consumer-rules.pro")
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    testOptions {
        unitTests {
            isIncludeAndroidResources = true
            isReturnDefaultValues = true
            all { t ->
                // lets `-Dbenchmark.write=true` reach the forked test JVM
                System.getProperty("benchmark.write")?.let { v -> t.systemProperty("benchmark.write", v) }
            }
        }
    }
}

kotlin {
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
    }
}

dependencies {
    // PdfBox-Android drags in the old bcprov-jdk15to18:1.72; use the current, patched jdk18on line instead.
    api(libs.pdfbox.android) { exclude(group = "org.bouncycastle") }
    implementation(libs.bouncycastle.prov)
    implementation(libs.bouncycastle.pkix)

    testImplementation(libs.junit)
    testImplementation(libs.robolectric)
    testImplementation(libs.androidx.test.core)
}
