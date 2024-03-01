rule JPCERTCC_TSC_Loader
{
	meta:
		description = "detect TSCookie Loader in memory"
		author = "JPCERT/CC Incident Response Group"
		id = "378cc8a3-6a76-50d1-b1d2-1a6ca1a75a46"
		date = "2021-08-16"
		modified = "2021-08-16"
		reference = "internal research"
		source_url = "https://github.com/JPCERTCC/MalConfScan//blob/19ec0d145535a6a4cfd37c0960114f455a8c343e/yara/rule.yara#L23-L35"
		license_url = "https://github.com/JPCERTCC/MalConfScan//blob/19ec0d145535a6a4cfd37c0960114f455a8c343e/LICENSE.txt"
		logic_hash = "c825253ba897f0f7310162d0473e645dc40b421e9251977384cca2fdc735f7a8"
		score = 75
		quality = 80
		tags = ""
		rule_usage = "memory scan"

	strings:
		$v1 = "Mozilla/4.0 (compatible; MSIE 8.0; Win32)" wide
		$b1 = { 68 78 0B 00 00 }

	condition:
		all of them
}
