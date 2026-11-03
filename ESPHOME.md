# ESPHome on the Series 4

ESPHome is the second firmware target for this board. It goes over the same LAN
OTA path as OpenBeken, and it needs no post-flash provisioning because the pin
map is compiled into the image.

Requires **ESPHome 2026.5.0 or newer**. That is the first release with the
BK7238 family and the `t1-2s` board at all.

## The config

This is the whole device definition. Copy it to `pc191ha-s4.yaml` and put your
own values in `secrets.yaml` beside it.

```yaml
esphome:
  name: pc191ha-s4
  friendly_name: Arlec PC191HA S4
  min_version: "2026.5.0"
  # Reads the chip's real MAC at runtime, so one image serves every unit. Without
  # this, every unit built from the same image advertises the same fallback AP
  # SSID and mDNS hostname, which collides the moment two are on one network.
  name_add_mac_suffix: true

bk72xx:
  board: t1-2s

# UART1 (RX1/TX1 = P10/P11) is the BL0942's bus. Same pins and baud as
# OpenBeken's `startDriver BL0942` default.
uart:
  id: bl0942_uart
  tx_pin: P11
  rx_pin: P10
  baud_rate: 4800

sensor:
  - platform: bl0942
    uart_id: bl0942_uart
    voltage:
      name: "Voltage"
    current:
      name: "Current"
    power:
      name: "Power"
    energy:
      name: "Energy"
    frequency:
      name: "Frequency"
    update_interval: 5s
  - platform: internal_temperature
    name: "Chip Temperature"
  - platform: wifi_signal
    name: "Wi-Fi Signal"
  - platform: uptime
    name: "Uptime"

# P8 is the relay indicator, active-high, driven from the relay's own state and
# never from Wi-Fi or API status. This board reuses the net LED for relay status.
output:
  - platform: gpio
    pin:
      number: P8
    id: relay_led

switch:
  - platform: gpio
    name: "Socket"
    pin:
      number: P26
    id: relay
    on_turn_on:
      - output.turn_on: relay_led
    on_turn_off:
      - output.turn_off: relay_led

# Blink the relay LED while the fallback AP is up, then restore the relay's real
# state the moment AP mode ends. Nothing else re-asserts the output, so the
# restore branch is required, not cosmetic.
interval:
  - interval: 250ms
    then:
      - lambda: |-
          static bool blink_state = false;
          static bool was_ap_active = false;
          bool ap_active = wifi::global_wifi_component->is_ap_active();
          if (ap_active) {
            blink_state = !blink_state;
            if (blink_state) {
              id(relay_led).turn_on();
            } else {
              id(relay_led).turn_off();
            }
          } else if (was_ap_active) {
            if (id(relay).state) {
              id(relay_led).turn_on();
            } else {
              id(relay_led).turn_off();
            }
          }
          was_ap_active = ap_active;

# P24 is the button, active-low with a pull-up. It toggles the relay.
binary_sensor:
  - platform: gpio
    pin:
      number: P24
      mode:
        input: true
        pullup: true
      inverted: true
    name: "Button"
    on_press:
      - switch.toggle: relay

wifi:
  ssid: !secret wifi_ssid
  password: !secret wifi_password
  ap:
    ssid: "pc191ha-s4 Fallback"
    password: !secret ap_fallback_password

api:
  encryption:
    key: !secret api_encryption_key

ota:
  platform: esphome

text_sensor:
  - platform: version
    name: "ESPHome Version"
  - platform: wifi_info
    ip_address:
      name: "IP Address"
    ssid:
      name: "Wi-Fi SSID"
    bssid:
      name: "Wi-Fi BSSID"
    mac_address:
      name: "MAC Address"

button:
  - platform: restart
    name: "Restart"
```

`secrets.yaml` needs four values:

```yaml
wifi_ssid: "your-ssid"
wifi_password: "your-password"
ap_fallback_password: "at-least-8-chars"
api_encryption_key: "base64-32-bytes"
```

Generate the API key with:

```bash
python -c "import base64, secrets; print(base64.b64encode(secrets.token_bytes(32)).decode())"
```

## No captive portal

The config above omits `captive_portal`. Real Wi-Fi is already baked into the
build, so the fallback AP's onboarding page is never needed, and dropping it
saves enough flash to fit the OTA partition. An ESPHome build with the portal
included overruns that partition by roughly 30 KB even with nothing else
superfluous in the config.

## Which build output to flash

A BK7238 build leaves three files that look like candidates. Only one is the
app.

| File | What it actually is |
|---|---|
| `firmware.bin` | A UF2 package, despite the name |
| `image_bk7238_app.ota.ug.bin` | LibreTiny's own OTA container: correct diff2ya header, but `bin_type` `PCZL` |
| `raw_firmware.bin` | The bare app off the linker. Flash this one |

`raw_firmware.bin` is already the bare logical app at base `0x10000`, with no
bootloader prefix and no CRC interleave to undo. Wrap it in the same `RCZL`
container the OpenBeken image uses and it goes over the same LAN path. See
[SERIES-4.md](SERIES-4.md) for the container format and the transfer.

## What is proven

ESPHome 2026.10.1 was flashed to a stock unit over the air with the whole
transfer captured on the wire. After the flash the unit reported its own
identity over the native API, with BL0942 metering live: voltage and frequency
sane, current and power at zero until calibrated. Relay state, chip temperature
and Wi-Fi signal all read correctly.

Metering is uncalibrated on first boot, the same as the OpenBeken bring-up. Add
`power_reference`, `voltage_reference` and `current_reference` to the `bl0942`
block once you have a steady resistive load to calibrate against.
