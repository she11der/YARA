rule SIGNATURE_BASE_FE_APT_Trojan_PL_PULSEJUMP_1
{
	meta:
		description = "Detects samples mentioned in PulseSecure report"
		author = "Mandiant"
		id = "690cc347-e60f-5cac-b65d-367ecee69251"
		date = "2021-04-16"
		modified = "2023-12-05"
		reference = "https://www.fireeye.com/blog/threat-research/2021/04/suspected-apt-actors-leverage-bypass-techniques-pulse-secure-zero-day.html"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_pulsesecure.yar#L137-L153"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		hash = "91ee23ee24e100ba4a943bb4c15adb4c"
		logic_hash = "c9aa2b9ef8aff14c20ed6597b1a71eafc3e3c181aabf9a3a68df18945207ff86"
		score = 75
		quality = 85
		tags = ""

	strings:
		$s1 = "open("
		$s2 = ">>/tmp/"
		$s3 = "syswrite("
		$s4 = /\}[\x09\x20]{0,32}elsif[\x09\x20]{0,32}\([\x09\x20]{0,32}\$\w{1,64}[\x09\x20]{1,32}eq[\x09\x20]{1,32}[\x22\x27](Radius|Samba|AD)[\x22\x27][\x09\x20]{0,32}\)\s{0,128}\{\s{0,128}@\w{1,64}[\x09\x20]{0,32}=[\x09\x20]{0,32}&/

	condition:
		all of them
}