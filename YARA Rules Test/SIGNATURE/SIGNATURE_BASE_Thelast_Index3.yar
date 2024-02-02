rule SIGNATURE_BASE_Thelast_Index3
{
	meta:
		description = "Webshells Auto-generated - file index3.php"
		author = "Florian Roth (Nextron Systems)"
		id = "41310217-b9a7-5360-80c4-7d0a3969f848"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/thor-webshells.yar#L8380-L8391"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		hash = "cceff6dc247aaa25512bad22120a14b4"
		logic_hash = "3700141ca2cf53f49618e2d4cab8866efccdce843921f1733b3d6260b8feea68"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s5 = "$err = \"<i>Your Name</i> Not Entered!</font></h2>Sorry, \\\"Your Name\\\" field is r"

	condition:
		all of them
}