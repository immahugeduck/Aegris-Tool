# AEGIS

AEGIS is a network and proximity diagnostics application built with React, TanStack Start, Zustand, and a Vercel/Nitro deployment target.

## Current capabilities

### Web/PWA

- public network identity and carrier/ASN metadata
- latency/jitter probing with a same-origin fallback
- bounded download/upload speed testing with loaded-latency measurement
- local speed-history comparison
- Web Bluetooth device pairing and experimental LE advertisement scanning when the browser exposes it
- heuristic BLE signature classification for common tracker/camera/recorder naming/service patterns
- privacy-minimized AI briefing using server-side xAI access
- installable PWA shell and mobile navigation

### Native Android companion

`android-agent/` adds capabilities normal websites cannot request:

- Android 12+ `BLUETOOTH_SCAN` and `BLUETOOTH_CONNECT` runtime permissions
- passive BLE advertisement scanning via `BluetoothLeScanner`
- RSSI, Tx power, manufacturer company ID/data, address and connectable metadata
- native Wi-Fi AP scanning for SSID/BSSID/RSSI/frequency/capabilities

The Android scanner is intentionally a separate native package. Adding a manifest permission to the PWA itself would not grant a Vercel-hosted web page Android radio access.

## Measurement boundaries

- BLE RSSI-derived distance is an estimate. It varies with transmit power, body obstruction, walls, antenna orientation, multipath and device behavior.
- The proximity plot does **not** measure direction. Angular position is only a display layout; the UI explicitly labels this.
- BLE signature matches are leads, not proof that a device is a camera, tracker, recorder, actively recording, malicious, or owned by any particular person.
- The Link page measures network-path behavior. It is not an RF spectrum analyzer.
- Browser Wi-Fi APIs do not expose nearby SSIDs/BSSIDs/channels; the Android scanner is the native path for that information.

## Privacy

The app keeps speed history and BLE observations in local Zustand persistence. The Intel briefing is user-initiated. Its server payload is minimized so raw public IPs, Bluetooth names, Bluetooth addresses and manufacturer payload bytes are not sent to the AI model.

Network identity resolution still contacts Cloudflare and, as a fallback, ipify. Speed testing uses Cloudflare speed endpoints with a same-origin probe fallback.

## Development

Core scripts are in `package.json`:

- `npm run dev`
- `npm run build`
- `npm run typecheck`
- `npm run lint`
- `npm test`

The extracted workspace did not include installed `node_modules`, so dependency-backed typecheck/build must be re-run after dependencies are installed in the target repository/CI environment.
