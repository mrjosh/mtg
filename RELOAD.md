# Config Reload Feature

## Overview

MTG now supports hot-reloading of secrets without restarting the proxy. This allows you to rotate secrets, add new ones, or remove compromised ones without any downtime.

## How to Use

### 1. Edit your config.toml

Modify the `secrets` array in your `config.toml` file:

```toml
secrets = [
  "ee9cb1f99593233def2412b475fddb330473746f726167652e676f6f676c65617069732e636f6d",
  "ee1d864f317ac80ee3a4716c328477d44d73746f726167652e676f6f676c65617069732e636f6d",
  "eenewsecrethere..."  # Add new secrets
]
```

### 2. Send SIGUSR1 signal to reload

```bash
# Find the MTG process ID
ps aux | grep "mtg run"

# Send reload signal
kill -USR1 <PID>
```

### 3. Check logs for confirmation

```json
{"level":"info","logger":"","message":"received SIGUSR1, reloading configuration"}
{"level":"info","count":3,"logger":"proxy","message":"secrets reloaded successfully"}
```

## Features

- **Zero downtime**: Active connections continue uninterrupted
- **Thread-safe**: Uses RWMutex to safely update secrets while serving requests
- **Atomic updates**: All secrets are updated at once
- **Error handling**: Invalid configs are rejected, keeping current secrets
- **Validation**: Empty secret arrays are rejected with a warning

## Implementation Details

### Changes Made

1. **mtglib/proxy.go**
   - Added `secretsMutex sync.RWMutex` for thread-safe access
   - Added `ReloadSecrets()` method to atomically update secrets
   - Protected secret access in `DomainFrontingAddress()` and `doFakeTLSHandshake()`

2. **internal/cli/run_proxy.go**
   - Added SIGUSR1 signal handler
   - Reads config file on signal
   - Calls `proxy.ReloadSecrets()` with new secrets

3. **Bug Fix**: Fixed multi-secret matching
   - `ParseClientHello()` modifies payload in-place
   - Now creates a fresh copy for each secret attempt
   - Fixes issue where only the first secret could match

## Use Cases

1. **Secret Rotation**: Gradually migrate clients to new secrets
   ```bash
   # Day 1: Add new secret
   secrets = ["old_secret", "new_secret"]
   kill -USR1 <PID>

   # Day 7: Remove old secret after clients migrate
   secrets = ["new_secret"]
   kill -USR1 <PID>
   ```

2. **Compromise Response**: Immediately revoke a compromised secret
   ```bash
   # Remove compromised secret from config
   vim config.toml
   # Reload immediately
   kill -USR1 <PID>
   ```

3. **Client Isolation**: Add secrets for different client groups
   ```bash
   secrets = [
     "secret_for_group_a",
     "secret_for_group_b",
     "secret_for_group_c"
   ]
   kill -USR1 <PID>
   ```

## Testing

```bash
# Generate a new secret
./mtg generate-secret -x storage.googleapis.com

# Add to config.toml and reload
kill -USR1 $(pgrep -f "mtg run")

# Verify in logs
tail -f /path/to/logs | grep "secrets reloaded"
```

## Notes

- Secrets must be in hex format (starting with `ee`) or valid base64
- Use `./mtg generate-secret -x <hostname>` for hex format
- The signal handler only reloads secrets, not other config options
- Works on Unix-like systems (Linux, macOS, BSD)
