rule SIGNATURE_BASE_Industroyer_Portscan_3_Output
{
	meta:
		description = "Detects Industroyer related custom port scaner output file"
		author = "Florian Roth (Nextron Systems)"
		id = "4469f056-674c-5a44-84a5-12a65b8586d5"
		date = "2017-06-13"
		modified = "2023-12-05"
		reference = "https://goo.gl/x81cSy"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_industroyer.yar#L102-L115"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "6a2fc7b66b1e93f523e08e12ba420d261bae198918bb09eac1a7cdecc04a6737"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "WSA library load complite." fullword ascii
		$s2 = "Connection refused" fullword ascii

	condition:
		all of them
}
