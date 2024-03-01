rule SIGNATURE_BASE_FE_Trojan_SH_ATRIUM_1
{
	meta:
		description = "Detects samples mentioned in PulseSecure report"
		author = "Mandiant"
		id = "c49441f4-a138-534c-a858-a7462ed865c9"
		date = "2021-04-16"
		modified = "2023-12-05"
		reference = "https://www.fireeye.com/blog/threat-research/2021/04/suspected-apt-actors-leverage-bypass-techniques-pulse-secure-zero-day.html"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_pulsesecure.yar#L29-L45"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "a631b7a8a11e6df3fccb21f4d34dbd8a"
		logic_hash = "672a293660d89d5d7d62a658c360bad0b6408611d8794744b17a81e6a75ceea7"
		score = 75
		quality = 60
		tags = ""

	strings:
		$s1 = "CGI::param("
		$s2 = "Cache-Control: no-cache"
		$s3 = "system("
		$s4 = /sed -i [^\r\n]{1,128}CGI::param\([^\r\n]{1,128}print[\x20\x09]{1,32}[^\r\n]{1,128}Cache-Control: no-cache[^\r\n]{1,128}print[\x20\x09]{1,32}[^\r\n]{1,128}Content-type: text\/html[^\r\n]{1,128}my [^\r\n]{1,128}=[\x09\x20]{0,32}CGI::param\([^\r\n]{1,128}system\(/

	condition:
		all of them
}
