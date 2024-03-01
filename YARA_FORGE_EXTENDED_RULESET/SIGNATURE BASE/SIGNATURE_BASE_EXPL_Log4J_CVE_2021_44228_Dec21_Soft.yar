rule SIGNATURE_BASE_EXPL_Log4J_CVE_2021_44228_Dec21_Soft : FILE CVE_2021_44228
{
	meta:
		description = "Detects indicators in server logs that indicate an exploitation attempt of CVE-2021-44228"
		author = "Florian Roth (Nextron Systems)"
		id = "87e536a5-cc11-528a-b100-4fa3b2b7bc0c"
		date = "2021-12-10"
		modified = "2021-12-20"
		reference = "https://twitter.com/h113sdx/status/1469010902183661568?s=20"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/expl_log4j_cve_2021_44228.yar#L68-L92"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "61a005060e2041afa5a9aa0b2a5e26cfc9a53cbafa78b15e4dd2c3b38127373a"
		score = 60
		quality = 85
		tags = "CVE-2021-44228"

	strings:
		$x01 = "${jndi:ldap:/"
		$x02 = "${jndi:rmi:/"
		$x03 = "${jndi:ldaps:/"
		$x04 = "${jndi:dns:/"
		$x05 = "${jndi:iiop:/"
		$x06 = "${jndi:http:/"
		$x07 = "${jndi:nis:/"
		$x08 = "${jndi:nds:/"
		$x09 = "${jndi:corba:/"
		$fp1 = "<html"
		$fp2 = "/nessus}"

	condition:
		1 of ($x*) and not 1 of ($fp*)
}
