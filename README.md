# Sandisk Extreme Counters

Lightweight python script to read counters from my sandisk extreme portable ssd (usb id `0x0781:0x55dd`) which unfortunately does not expose SMART data through its USB bridge.

However, we can send `SCSI LOG SENSE` directly to the device to expose some of these counters. There are more counters in these pages, but I am too lazy to figure out what they are.

**Info:** All of these counters were reverse engineered by experimentation and are not officially documented (and hence may be incorrect).

Extended from [smartmontools issue #526](https://github.com/smartmontools/smartmontools/issues/526)

## Usage

```
python sandisk_55dd_logs.py <physical disk number> --all
```
