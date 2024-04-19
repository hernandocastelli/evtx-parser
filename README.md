# Evtx Parser

Evtx Parser is a Python script for analyzing Windows Event Log files (evtx). It provides functionalities to extract information from security logs including counting occurrences of specific [Event IDs](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624), displaying header information of the log file, and filtering events based on Event IDs and fields.

## Examples

- Count occurrences of specific Event IDs:
```
evtxparser.py -e Security.evtx
```
- Show header information of the logfile:
```
evtxparser.py -i Security.evtx
```
- Filter events based on specified Event IDs and fields:
```
evtxparser.py Security.evtx -el 4624,4625 -fl IpAddress,LogonType
```

## License

This project is licensed under the MIT License.