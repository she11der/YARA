rule SIGNATURE_BASE_WEBSHELL_PAS_Webshell___FILE
{
	meta:
		description = "Detects P.A.S. PHP webshell - Based on DHS/FBI JAR-16-2029 (Grizzly  Steppe)"
		author = "FR/ANSSI/SDO (modified by Florian Roth)"
		id = "862aab77-936e-524c-8669-4f48730f4ed5"
		date = "2021-02-15"
		modified = "2023-12-05"
		reference = "https://www.cert.ssi.gouv.fr/uploads/CERTFR-2021-CTI-005.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_sandworm_centreon.yar#L10-L28"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "977ee0fdf0e92ccea6b71fea7b2c7aed2965c6966d8af86230ccb0f95b286694"
		score = 70
		quality = 85
		tags = "FILE"

	strings:
		$php = "<?php"
		$strreplace = "(str_replace("
		$md5 = ".substr(md5(strrev($"
		$gzinflate = "gzinflate"
		$cookie = "_COOKIE"
		$isset = "isset"

	condition:
		( filesize >20KB and filesize <200KB) and all of them
}