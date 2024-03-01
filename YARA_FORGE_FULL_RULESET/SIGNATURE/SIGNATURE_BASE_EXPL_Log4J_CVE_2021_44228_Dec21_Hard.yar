rule SIGNATURE_BASE_EXPL_Log4J_CVE_2021_44228_Dec21_Hard : FILE CVE_2021_44228
{
	meta:
		description = "Detects indicators in server logs that indicate the exploitation of CVE-2021-44228"
		author = "Florian Roth"
		id = "5297c42d-7138-507d-a3eb-153afe522816"
		date = "2021-12-10"
		modified = "2023-10-23"
		reference = "https://twitter.com/h113sdx/status/1469010902183661568?s=20"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/expl_log4j_cve_2021_44228.yar#L118-L140"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "9a4fc285dd1680ebc8a1042eeb5fbba73b9e2df70678adf3163122d84405325e"
		score = 75
		quality = 35
		tags = "CVE-2021-44228"

	strings:
		$x1 = /\$\{jndi:(ldap|ldaps|rmi|dns|iiop|http|nis|nds|corba):\/[\/]?[a-z-\.0-9]{3,120}:[0-9]{2,5}\/[a-zA-Z\.]{1,32}\}/
		$x2 = "Reference Class Name: foo"
		$fp1r = /(ldap|rmi|ldaps|dns):\/[\/]?(127\.0\.0\.1|192\.168\.|172\.[1-3][0-9]\.|10\.)/
		$fpg2 = "<html"
		$fpg3 = "<HTML"
		$fp1 = "/QUALYSTEST" ascii
		$fp2 = "w.nessus.org/nessus"
		$fp3 = "/nessus}"

	condition:
		1 of ($x*) and not 1 of ($fp*)
}
