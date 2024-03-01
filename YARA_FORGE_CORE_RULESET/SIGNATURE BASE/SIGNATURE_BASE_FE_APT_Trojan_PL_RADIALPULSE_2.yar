rule SIGNATURE_BASE_FE_APT_Trojan_PL_RADIALPULSE_2
{
	meta:
		description = "Detects samples mentioned in PulseSecure report"
		author = "Mandiant"
		id = "dc941935-aec7-54b6-a278-f1453b9785df"
		date = "2021-04-16"
		modified = "2023-12-05"
		reference = "https://www.fireeye.com/blog/threat-research/2021/04/suspected-apt-actors-leverage-bypass-techniques-pulse-secure-zero-day.html"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_pulsesecure.yar#L191-L208"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		hash = "4a2a7cbc1c8855199a27a7a7b51d0117"
		logic_hash = "4ade993176c918ec23e99fc585e9ab14d9f9e93a7eca00f2c3b0ebbd13d6ec5b"
		score = 75
		quality = 85
		tags = ""

	strings:
		$s1 = "open(*fd,"
		$s2 = "syswrite(*fd,"
		$s3 = "close(*fd);"
		$s4 = /open\(\*fd,[\x09\x20]{0,32}[\x22\x27]>>\/tmp\/[\w.]{1,128}[\x22\x27]\);[\x09\x20]{0,32}syswrite\(\*fd,[\x09\x20]{0,32}/
		$s5 = /syswrite\(\*fd,[\x09\x20]{0,32}[\x22\x27][\w]{1,128}=\$\w{1,128} ?[\x22\x27],[\x09\x20]{0,32}5000\)/

	condition:
		all of them
}
