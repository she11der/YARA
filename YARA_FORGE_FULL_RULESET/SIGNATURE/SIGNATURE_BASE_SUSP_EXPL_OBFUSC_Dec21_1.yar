rule SIGNATURE_BASE_SUSP_EXPL_OBFUSC_Dec21_1 : CVE_2021_44228 FILE
{
	meta:
		description = "Detects obfuscation methods used to evade detection in log4j exploitation attempt of CVE-2021-44228"
		author = "Florian Roth (Nextron Systems)"
		id = "b8f56711-7922-54b9-9ce2-6ba05d64c80d"
		date = "2021-12-11"
		modified = "2022-11-08"
		reference = "https://twitter.com/testanull/status/1469549425521348609"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/expl_log4j_cve_2021_44228.yar#L182-L211"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "d6ffb70da82fe16e7a76feb31c01aa3e0cfc5625cc0e2b237ec851c646550839"
		score = 60
		quality = 85
		tags = "CVE-2021-44228, FILE"

	strings:
		$f1 = { 24 7B 6C 6F 77 65 72 3A ?? 7D }
		$f2 = { 24 7B 75 70 70 65 72 3A ?? 7D }
		$x3 = "$%7blower:"
		$x4 = "$%7bupper:"
		$x5 = "%24%7bjndi:"
		$x6 = "$%7Blower:"
		$x7 = "$%7Bupper:"
		$x8 = "%24%7Bjndi:"
		$fp1 = "<html"

	condition:
		(1 of ($x*) or filesize <200KB and 1 of ($f*)) and not 1 of ($fp*)
}
