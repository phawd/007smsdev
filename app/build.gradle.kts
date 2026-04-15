import java.util.Properties

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}

kotlin {
    jvmToolchain(25)
}

// Load signing and API configuration from local.properties (not committed to VCS)
val localProps = Properties()
val localPropsFile = rootProject.file("local.properties")
if (localPropsFile.exists()) {
    localProps.load(localPropsFile.inputStream())
}

android {
    namespace = "com.smstest.app"
    compileSdk = 35

    defaultConfig {
        // API key is read from local.properties or environment variable; never hard-code secrets.
        // An empty string is intentional for CI/debug builds that don't use the Apify API.
        val apifyApiKey = localProps.getProperty("apify.api.key")
            ?: System.getenv("APIFY_API_KEY")
            ?: ""
        buildConfigField("String", "APIFY_API_KEY", "\"$apifyApiKey\"")
        applicationId = "com.smstest.app"
        minSdk = 24
        targetSdk = 35
        versionCode = 1
        versionName = "1.0.0"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        vectorDrawables {
            useSupportLibrary = true
        }
    }

    sourceSets {
        getByName("androidTest") {
            java.srcDirs("src/androidTest/java", "src/androidTest/kotlin")
        }
        getByName("test") {
            java.srcDirs("src/test/java")
        }
    }

    // Release signing – keystore credentials are read from local.properties or environment.
    // See docs/APK_BUILD_GUIDE.md for setup instructions.
    val keystoreFile = localProps.getProperty("release.keystore.file")
        ?: System.getenv("RELEASE_KEYSTORE_FILE")
    val keystorePassword = localProps.getProperty("release.keystore.password")
        ?: System.getenv("RELEASE_KEYSTORE_PASSWORD")
    val keyAlias = localProps.getProperty("release.key.alias")
        ?: System.getenv("RELEASE_KEY_ALIAS")
    val keyPassword = localProps.getProperty("release.key.password")
        ?: System.getenv("RELEASE_KEY_PASSWORD")

    if (keystoreFile != null && keystorePassword != null
        && keyAlias != null && keyPassword != null) {
        signingConfigs {
            create("release") {
                storeFile = file(keystoreFile)
                storePassword = keystorePassword
                this.keyAlias = keyAlias
                this.keyPassword = keyPassword
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
            // Apply signing config when keystore credentials are available
            val releaseSigningConfig = signingConfigs.findByName("release")
            if (releaseSigningConfig != null) {
                signingConfig = releaseSigningConfig
            }
        }
        debug {
            applicationIdSuffix = ".debug"
            isDebuggable = true
        }
    }
    testOptions {
        unitTests {
            isIncludeAndroidResources = true
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_21
        targetCompatibility = JavaVersion.VERSION_21
    }
    
    kotlinOptions {
        jvmTarget = "21"  // Android max supported JVM target
    }
    
    buildFeatures {
        compose = true
        buildConfig = true
    }
    
    packaging {
        resources {
            excludes += "/META-INF/{AL2.0,LGPL2.1}"
        }
    }
}

dependencies {
    // Core Android
    implementation("androidx.core:core-ktx:1.15.0")
    implementation("androidx.appcompat:appcompat:1.7.0")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.7")
    implementation("androidx.activity:activity-compose:1.9.3")
    
    // Jetpack Compose
    implementation(platform("androidx.compose:compose-bom:2024.11.00"))
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-graphics")
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.material:material-icons-extended")
    
    // Navigation
    implementation("androidx.navigation:navigation-compose:2.8.5")
    
    // ViewModel
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.8.7")
    
    // Coroutines
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.9.0")
    
    // Permissions
    implementation("com.google.accompanist:accompanist-permissions:0.36.0")
    
    // DataStore
    implementation("androidx.datastore:datastore-preferences:1.1.1")
    
    // WorkManager for background operations
    implementation("androidx.work:work-runtime-ktx:2.10.0")
    
    // Testing
    testImplementation("junit:junit:4.13.2")
    testImplementation("org.robolectric:robolectric:4.13")
    testImplementation("androidx.test:core:1.6.1")
    testImplementation("org.mockito:mockito-core:5.14.2")
    androidTestImplementation("androidx.test.ext:junit:1.2.1")
    androidTestImplementation("androidx.test.espresso:espresso-core:3.6.1")
    androidTestImplementation(platform("androidx.compose:compose-bom:2024.11.00"))
    androidTestImplementation("androidx.compose.ui:ui-test-junit4")
    debugImplementation("androidx.compose.ui:ui-tooling")
    debugImplementation("androidx.compose.ui:ui-test-manifest")
}
