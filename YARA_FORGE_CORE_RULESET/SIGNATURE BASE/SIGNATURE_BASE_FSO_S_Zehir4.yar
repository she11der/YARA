rule SIGNATURE_BASE_FSO_S_Zehir4
{
	meta:
		description = "Webshells Auto-generated - file zehir4.asp"
		author = "Florian Roth (Nextron Systems)"
		id = "9f1adcd6-b721-54ef-a20f-c3a353629a40"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/thor-webshells.yar#L7302-L7313"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		hash = "5b496a61363d304532bcf52ee21f5d55"
		logic_hash = "6bcfb1ee40403394bf996ecbe1bb17f9afa0c3ba9e1906881b94bbc785b4a510"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s5 = " byMesaj "

	condition:
		all of them
}
