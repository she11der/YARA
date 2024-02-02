rule SIGNATURE_BASE_Exp_EPS_CVE20152545___CVE_2015_2545_FILE
{
	meta:
		description = "Detects EPS Word Exploit CVE-2015-2545"
		author = "Florian Roth (Nextron Systems)"
		id = "9a5f0554-b588-5b82-93df-0fdfba2af2da"
		date = "2017-07-19"
		modified = "2023-12-05"
		reference = "Internal Research - ME"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/exploit_cve_2015_2545.yar#L2-L16"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "e1aac80a06dd71352d2776b4dfccce901d47363459853a37669af69be6e962c7"
		score = 70
		quality = 85
		tags = "CVE-2015-2545, FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "word/media/image1.eps" ascii
		$s2 = "-la;7(la+" ascii

	condition:
		uint16(0)==0x4b50 and ($s1 and #s2>20)
}