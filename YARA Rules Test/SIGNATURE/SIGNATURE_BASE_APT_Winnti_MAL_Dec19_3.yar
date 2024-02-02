rule SIGNATURE_BASE_APT_Winnti_MAL_Dec19_3
{
	meta:
		description = "Detects Winnti malware"
		author = "Unknown"
		id = "2e001c91-0794-5940-ad8c-8e58a01e100c"
		date = "2019-12-06"
		modified = "2023-12-05"
		reference = "https://www.verfassungsschutz.de/download/broschuere-2019-12-bfv-cyber-brief-2019-01.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_winnti.yar#L203-L219"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "d09f948c9bf685de64e8a6f1c95d95b806651866f3364d5d9b8b2351c1a68be3"
		score = 75
		quality = 85
		tags = ""

	strings:
		$b1 = { 0F B7 ?? 16 [0-1] (81 E? | 25) 00 20 [0-2] [8] 8B ?? 50 41 B9 40 00 00 00 41 B8 00 10 00 00 }
		$b2 = { 8B 40 28 [5-8] 48 03 C8 48 8B C1 [5-8] 48 89 41 28 }
		$b3 = { 48 6B ?? 28 [5-8] 8B ?? ?? 10 [5-8] 48 6B ?? 28 [5-8] 8B ?? ?? 14 }
		$b4 = { 83 B? 90 00 00 00 00 0F 84 [9-12] 83 B? 94 00 00 00 00 0F 84 }
		$b5 = { (45 | 4D) (31 | 33) C0 BA 01 00 00 00 [10-16] FF 5? 28 [0-1] (84 | 85) C0 }

	condition:
		(4 of ($b*))
}