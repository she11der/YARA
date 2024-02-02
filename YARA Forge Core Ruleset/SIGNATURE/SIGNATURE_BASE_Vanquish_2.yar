rule SIGNATURE_BASE_Vanquish_2
{
	meta:
		description = "Webshells Auto-generated - file vanquish.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "6736cad6-cba1-5b6f-ae05-e2b980280479"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/thor-webshells.yar#L8866-L8877"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		hash = "2dcb9055785a2ee01567f52b5a62b071"
		logic_hash = "428dc4e6d8bcc888e6f99f69ee9f211aa029d3486b99b9716d09709dc391d9a2"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s2 = "Vanquish - DLL injection failed:"

	condition:
		all of them
}