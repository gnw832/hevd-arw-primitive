# HEVD arbitrary read/write
privilege escalation in Windows 10 version 25H2 (Build 26200.746) from admin user to SYSTEM
using the HEVD, arbitrary write IOCTL `0x22200b`. no validation of usermode buffers with appropriate `ProbeForRead()` or `ProbeForWrite`, which exposes the vulnerability

## usage
* download HEVD driver [hacksys extreme vulnerable driver (HEVD)](https://github.com/hacksysteam/HackSysExtremeVulnerableDriver)
* `sc create` service for driver, then `sc start` service
* once driver is loaded and running, compile binary executable in visual studio
* run binary

## note
* educational purposes only.
* this project is not intended for real world exploitation, and is a recreation of a historical driver vulnerability. should not be used on systems you are not authorized to test on
