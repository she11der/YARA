rule SIGNATURE_BASE_LOG_EXPL_Adselfservice_CVE_2021_40539_Weblog_Sep21_1 : LOG CVE_2021_40539 FILE
{
	meta:
		description = "Detects suspicious log lines produeced during the exploitation of ADSelfService vulnerability CVE-2021-40539"
		author = "Florian Roth (Nextron Systems)"
		id = "015957a6-8778-5836-af94-6e6d3838f693"
		date = "2021-09-20"
		modified = "2023-12-05"
		reference = "https://us-cert.cisa.gov/ncas/alerts/aa21-259a"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/expl_adselfservice_cve_2021_40539.yar#L16-L29"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "bc27afd63d32ac95711e5b4e70764fe0d1bcbb4b4b9b4e3f324e058bba2ef8f6"
		score = 60
		quality = 85
		tags = "CVE-2021-40539, FILE"

	strings:
		$x1 = "/ServletApi/../RestApi/LogonCustomization" ascii wide
		$x2 = "/ServletApi/../RestAPI/Connection" ascii wide

	condition:
		filesize <50MB and 1 of them
}
