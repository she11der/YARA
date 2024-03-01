rule SIGNATURE_BASE_Ebayid_Index3
{
	meta:
		description = "Webshells Auto-generated - file index3.php"
		author = "Florian Roth (Nextron Systems)"
		id = "4fc30150-7b44-53c4-888c-faf651495407"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/thor-webshells.yar#L7798-L7809"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		hash = "0412b1e37f41ea0d002e4ed11608905f"
		logic_hash = "47660cb71d6787683e51aa14fc0f4a9d6f1c59517b77bfe4135098a0020ded11"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s8 = "$err = \"<i>Your Name</i> Not Entered!</font></h2>Sorry, \\\"You"

	condition:
		all of them
}
