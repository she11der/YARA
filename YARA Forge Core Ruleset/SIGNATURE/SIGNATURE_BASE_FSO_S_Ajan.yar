rule SIGNATURE_BASE_FSO_S_Ajan
{
	meta:
		description = "Webshells Auto-generated - file ajan.asp"
		author = "Florian Roth (Nextron Systems)"
		id = "03bf98b9-c8c5-5b9f-b0cd-700c5ed58eac"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/thor-webshells.yar#L8680-L8691"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		hash = "22194f8c44524f80254e1b5aec67b03e"
		logic_hash = "a7766caae5845ce43cff2212c25fea9a78979d10c79d8c40290b5c1471b101cd"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s4 = "entrika.write \"BinaryStream.SaveToFile"

	condition:
		all of them
}