# Release Signing

## Generate a Keystore

```bash
keytool -genkey -v -keystore mega-provider.jks -alias mega-provider \
  -keyalg RSA -keysize 2048 -validity 10000
```

## Set Environment Variables

Before building a release APK, export these variables:

```bash
export KEYSTORE_PATH=/path/to/mega-provider.jks
export KEYSTORE_PASSWORD=your_store_password
export KEY_ALIAS=mega-provider
export KEY_PASSWORD=your_key_password
```

Then build the release:

```bash
./gradlew assembleRelease
```

## CI/CD (GitHub Actions)

For CI builds, store the following as GitHub Secrets:

| Secret              | Description                                |
|---------------------|--------------------------------------------|
| `KEYSTORE_BASE64`   | Base64-encoded `.jks` file                 |
| `KEYSTORE_PASSWORD` | Keystore password                          |
| `KEY_ALIAS`         | Key alias (e.g. `mega-provider`)           |
| `KEY_PASSWORD`      | Key password                               |

Encode your keystore:

```bash
base64 -w 0 mega-provider.jks > keystore_base64.txt
```

Copy the contents of `keystore_base64.txt` into the `KEYSTORE_BASE64` secret.
