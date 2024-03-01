rule SIGNATURE_BASE_EXPL_LOG_CVE_2021_27065_Exchange_Forensic_Artefacts_Mar21_1 : LOG CVE_2021_27065
{
	meta:
		description = "Detects forensic artefacts found in HAFNIUM intrusions exploiting CVE-2021-27065"
		author = "Florian Roth (Nextron Systems)"
		id = "dcc1f741-cab0-5a0b-a261-a6bd05989723"
		date = "2021-03-02"
		modified = "2023-12-05"
		reference = "https://www.volexity.com/blog/2021/03/02/active-exploitation-of-microsoft-exchange-zero-day-vulnerabilities/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_hafnium_log_sigs.yar#L2-L13"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "9306cf177928266ea921461e9da80ad5bb37e1e0848559898a414956cfbc2b49"
		score = 75
		quality = 85
		tags = "CVE-2021-27065"

	strings:
		$s1 = "S:CMD=Set-OabVirtualDirectory.ExternalUrl='" ascii wide fullword

	condition:
		1 of them
}
