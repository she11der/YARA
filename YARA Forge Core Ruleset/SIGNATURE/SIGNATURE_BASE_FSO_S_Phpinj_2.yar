rule SIGNATURE_BASE_FSO_S_Phpinj_2
{
	meta:
		description = "Webshells Auto-generated - file phpinj.php"
		author = "Florian Roth (Nextron Systems)"
		id = "db8f835e-eb13-50f3-a60b-7d8ffcaa5eaa"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/thor-webshells.yar#L8650-L8661"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		hash = "dd39d17e9baca0363cc1c3664e608929"
		logic_hash = "12af5182b94f01ac4fbdee92c007556aaa7f196aca116575803cedd84b81f3b0"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s9 = "<? system(\\$_GET[cpc]);exit; ?>' ,0 ,0 ,0 ,0 INTO"

	condition:
		all of them
}