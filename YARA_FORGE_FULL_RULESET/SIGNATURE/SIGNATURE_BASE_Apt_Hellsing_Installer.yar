rule SIGNATURE_BASE_Apt_Hellsing_Installer : FILE
{
	meta:
		description = "detection for Hellsing xweber/msger installers"
		author = "Kaspersky Lab"
		id = "0aca838e-813a-59ee-8a04-7d2f4e854075"
		date = "2015-04-07"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_hellsing_kaspersky.yar#L31-L54"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "556898e9507835d93e2cf7e21e997b6e64dc154ac675b429f5f8226bf929309c"
		score = 75
		quality = 85
		tags = "FILE"
		version = "1.0"
		filetype = "PE"

	strings:
		$cmd = "cmd.exe /c ping 127.0.0.1 -n 5&cmd.exe /c del /a /f \"%s\""
		$a1 = "xweber_install_uac.exe"
		$a2 = "system32\\cmd.exe" wide
		$a4 = "S11SWFOrVwR9UlpWRVZZWAR0U1aoBHFTUl2oU1Y="
		$a5 = "S11SWFOrVwR9dnFTUgRUVlNHWVdXBFpTVgRdUlpWRVZZWARdUqhZVlpFR1kEUVNSXahTVgRaU1YEUVNSXahTVl1SWwRZValdVFFZUqgQBF1SWlZFVllYBFRTVqg="
		$a6 = "7dqm2ODf5N/Y2N/m6+br3dnZpunl44g="
		$a7 = "vd/m7OXd2ai/5u7a59rr7Ki45drcqMPl5t/c5dqIZw=="
		$a8 = "vd/m7OXd2ai/usPl5qjY2uXp69nZqO7l2qjf5u7a59rr7Kjf5tzr2u7n6euo4+Xm39zl2qju5dqo4+Xm39zl2t/m7ajr19vf2OPr39rj5eaZmqbs5OSINjl2tyI"
		$a9 = "C:\\Windows\\System32\\sysprep\\sysprep.exe" wide
		$a10 = "%SystemRoot%\\system32\\cmd.exe" wide
		$a11 = "msger_install.dll"
		$a12 = {00 65 78 2E 64 6C 6C 00}

	condition:
		uint16(0)==0x5a4d and ($cmd and (2 of ($a*))) and filesize <500000
}
