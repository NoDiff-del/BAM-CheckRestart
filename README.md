# BAMCheckRestart

Verifies the BAM creation date and retrieves the PC logon time, providing a clear comparison between both timestamps to assist in analysis.

## Functionality

- Analyze the System process for the thread bam.sys and retrieve its creation date.
- Provide the logon time to calculate and compare the time difference.

## Note

### Windows 10/11

1. Upon opening, all necessary information should be immediately available

2.  This method is compatible with Windows 10 and Windows 11, although it may not work reliably on certain Windows 11 builds.
