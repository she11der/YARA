rule SIGNATURE_BASE_EXPL_Log4J_CVE_2021_44228_Dec21_OBFUSC : CVE_2021_44228
{
	meta:
		description = "Detects obfuscated indicators in server logs that indicate an exploitation attempt of CVE-2021-44228"
		author = "Florian Roth (Nextron Systems)"
		id = "d7c4092a-6ffc-5a89-b73a-f7f0ac984cbd"
		date = "2021-12-12"
		modified = "2021-12-13"
		reference = "https://twitter.com/h113sdx/status/1469010902183661568?s=20"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/expl_log4j_cve_2021_44228.yar#L94-L116"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "00231db2ae83a89c187dbde1f2bc67fdaedcf1cbdf872afdcc374d2d0abee515"
		score = 60
		quality = 85
		tags = "CVE-2021-44228"

	strings:
		$x1 = "$%7Bjndi:"
		$x2 = "%2524%257Bjndi"
		$x3 = "%2F%252524%25257Bjndi%3A"
		$x4 = "${jndi:${lower:"
		$x5 = "${::-j}${"
		$x6 = "${${env:BARFOO:-j}"
		$x7 = "${::-l}${::-d}${::-a}${::-p}"
		$x8 = "${base64:JHtqbmRp"
		$fp1 = "<html"

	condition:
		1 of ($x*) and not 1 of ($fp*)
}
