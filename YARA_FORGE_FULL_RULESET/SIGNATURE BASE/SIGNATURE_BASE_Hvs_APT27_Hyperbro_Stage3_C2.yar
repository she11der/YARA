import "pe"

rule SIGNATURE_BASE_Hvs_APT27_Hyperbro_Stage3_C2
{
	meta:
		description = "HyperBro Stage 3 C2 path and user agent detection - also tested in memory"
		author = "Marc Stroebel"
		id = "d1fe03b9-440c-5127-9572-dddcd5c9966b"
		date = "2022-02-07"
		modified = "2023-12-05"
		reference = "https://www.hvs-consulting.de/en/threat-intelligence-report-emissary-panda-apt27"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_apt27_hyperbro.yar#L86-L100"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "676df1eaa782c6b876df138a0ddddc3c63e277b84d4414b044314ee219674420"
		score = 50
		quality = 81
		tags = ""
		hash1 = "624e85bd669b97bc55ed5c5ea5f6082a1d4900d235a5d2e2a5683a04e36213e8"

	strings:
		$s1 = "api/v2/ajax" ascii wide nocase
		$s2 = "Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/34.0.1847.116 Safari/537.36" ascii wide nocase

	condition:
		all of them
}
