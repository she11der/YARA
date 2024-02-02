rule SIGNATURE_BASE_FE_APT_Trojan_PL_RADIALPULSE_3
{
	meta:
		description = "Detects samples mentioned in PulseSecure report"
		author = "Mandiant"
		id = "8a597521-c873-5bcc-85e6-5a0a061fffb7"
		date = "2021-04-16"
		modified = "2023-12-05"
		reference = "https://www.fireeye.com/blog/threat-research/2021/04/suspected-apt-actors-leverage-bypass-techniques-pulse-secure-zero-day.html"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_pulsesecure.yar#L209-L226"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		hash = "4a2a7cbc1c8855199a27a7a7b51d0117"
		logic_hash = "025308591e058de284f949fd4f788e4a4f46bb2f6c0e1161237f1f811d8179ba"
		score = 75
		quality = 85
		tags = ""

	strings:
		$s1 = "open(*fd,"
		$s2 = "syswrite(*fd,"
		$s3 = "close(*fd);"
		$s4 = /open\(\*fd,[\x09\x20]{0,32}[\x22\x27]>>\/tmp\/dsstartssh\.statementcounters[\x22\x27]\);[\x09\x20]{0,32}syswrite\(\*fd,[\x09\x20]{0,32}/
		$s5 = /syswrite\(\*fd,[\x09\x20]{0,32}[\x22\x27][\w]{1,128}=\$username ?[\x22\x27],[\x09\x20]{0,32}\d{4}\)/

	condition:
		all of them
}