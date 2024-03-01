rule SIGNATURE_BASE_FSO_S_Indexer_2
{
	meta:
		description = "Webshells Auto-generated - file indexer.asp"
		author = "Florian Roth (Nextron Systems)"
		id = "8ef79a60-fa8c-51ee-bd87-f5467a66099b"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/thor-webshells.yar#L8728-L8739"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		hash = "135fc50f85228691b401848caef3be9e"
		logic_hash = "8cf4c8fb1e985adbed2cf20578fcfc14240f6d9fe6062bbe3fe2f895f58bc172"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s5 = "<td>Nerden :<td><input type=\"text\" name=\"nerden\" size=25 value=index.html></td>"

	condition:
		all of them
}
