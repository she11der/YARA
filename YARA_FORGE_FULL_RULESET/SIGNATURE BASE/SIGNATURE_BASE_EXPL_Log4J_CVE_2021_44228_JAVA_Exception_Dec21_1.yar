rule SIGNATURE_BASE_EXPL_Log4J_CVE_2021_44228_JAVA_Exception_Dec21_1 : CVE_2021_44228
{
	meta:
		description = "Detects exceptions found in server logs that indicate an exploitation attempt of CVE-2021-44228"
		author = "Florian Roth (Nextron Systems)"
		id = "82cf337e-4ea1-559b-a7b8-512a07adf06f"
		date = "2021-12-12"
		modified = "2023-12-05"
		reference = "https://gist.github.com/Neo23x0/e4c8b03ff8cdf1fa63b7d15db6e3860b"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/expl_log4j_cve_2021_44228.yar#L51-L66"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "98eabec4ad2f5c4d22db9c3bebdc82c8dc6723599748360875fc7b613b1019ab"
		score = 60
		quality = 85
		tags = "CVE-2021-44228"

	strings:
		$xa1 = "header with value of BadAttributeValueException: "
		$sa1 = ".log4j.core.net.JndiManager.lookup(JndiManager"
		$sa2 = "Error looking up JNDI resource"

	condition:
		$xa1 or all of ($sa*)
}
