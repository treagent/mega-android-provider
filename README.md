# MEGA Android DocumentsProvider

An Android app that exposes your MEGA.nz cloud storage as a drive in Android's
native file manager via the **Storage Access Framework (SAF) DocumentsProvider**
API.

## Features

- Appears as **"MEGA"** in any Android file manager (Files by Google, Solid
  Explorer, etc.)
- Browse folders and files on your MEGA account
- Download / open files from the file manager
- Upload files by copying them into the MEGA drive
- Create and delete files and folders
- Secure authentication — session stored in Android Keystore via
  EncryptedSharedPreferences

## Prerequisites

- [Android Studio](https://developer.android.com/studio) (Hedgehog 2023.1+ recommended)
- JDK 17
- Android SDK with API 34 (compile SDK) and API 24+ device/emulator

## MEGA SDK Setup

This app uses the [MEGA C++ SDK](https://github.com/meganz/sdk) Android
bindings (`nz.mega.sdk.*`). Because MEGA does not publish a simple Maven
artifact, you need to provide the SDK AAR manually:

### Option A — Build from source (recommended)

1. Clone the MEGA SDK: `git clone https://github.com/meganz/sdk.git mega-sdk`
2. Follow their [Android build instructions](https://github.com/meganz/sdk/blob/master/bindings/java/android/README.md)
   to produce `sdk/bindings/java/android/build/outputs/aar/megasdk-android-release.aar`
3. Copy the AAR into this project:
   ```bash
   mkdir -p app/libs
   cp mega-sdk/bindings/java/android/build/outputs/aar/*.aar app/libs/megasdk-android.aar
   ```
4. Uncomment the local AAR dependency in `app/build.gradle.kts`:
   ```kotlin
   implementation(files("libs/megasdk-android.aar"))
   ```

### Option B — Use MEGA's own Android app modules

If you have access to the [official MEGA Android app](https://github.com/nicosResearchWorkspace/android)
source, you can reference its SDK module directly.

### Option C — JitPack (if available)

If MEGA publishes to JitPack, add to `app/build.gradle.kts`:
```kotlin
implementation("com.github.meganz:sdk:TAG")
```

## MEGA API Key

1. Go to [https://mega.nz/sdk](https://mega.nz/sdk) and request an API key
2. Open `app/src/main/kotlin/com/mega/provider/MegaClientHolder.kt`
3. Replace `YOUR_MEGA_API_KEY` with your key:
   ```kotlin
   private const val MEGA_API_KEY = "AbCdEf1234..."
   ```

## Build & Run

1. Open the project in Android Studio (`File → Open → select this folder`)
2. Ensure the MEGA SDK AAR is in `app/libs/` (see above)
3. Sync Gradle (Android Studio will prompt you)
4. Connect a device or start an emulator (API 24+)
5. Run the `app` configuration

## Usage

1. Launch the app and sign in with your MEGA email + password
2. Open any file manager app (Files by Google, Solid Explorer, etc.)
3. Look for **"MEGA"** in the side drawer / storage providers list
4. Browse, open, copy, and manage files as if MEGA were a local drive

## Project Structure

```
app/src/main/
├── AndroidManifest.xml          # Provider + Activity declarations
├── kotlin/com/mega/provider/
│   ├── MegaProviderApp.kt       # Application class — initializes SDK
│   ├── MegaClientHolder.kt      # Singleton wrapping MegaApiAndroid
│   ├── MegaSessionManager.kt    # Encrypted session storage
│   ├── MegaDocumentsProvider.kt # SAF DocumentsProvider implementation
│   └── LoginActivity.kt         # Login UI
└── res/
    ├── layout/activity_login.xml
    ├── values/strings.xml
    ├── values/themes.xml
    └── drawable/ic_mega.xml
```

## Security

- No credentials are hardcoded
- The MEGA session string is stored in `EncryptedSharedPreferences` backed by
  Android Keystore (AES-256-GCM)
- Deletion moves files to MEGA's rubbish bin (not permanent delete)

## Tech Stack

- **Language:** Kotlin
- **Min SDK:** API 24 (Android 7.0)
- **Build:** Gradle with Kotlin DSL
- **Auth storage:** AndroidX Security (EncryptedSharedPreferences)
- **MEGA integration:** nz.mega.sdk (MegaApiAndroid)

## License

This project is provided as-is for educational purposes.
