rule SIGNATURE_BASE_FSO_S_Casus15_2
{
	meta:
		description = "Webshells Auto-generated - file casus15.php"
		author = "Florian Roth (Nextron Systems)"
		id = "d3f67fe9-a93f-504a-8b14-a815135d562f"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/thor-webshells.yar#L7837-L7848"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		hash = "8d155b4239d922367af5d0a1b89533a3"
		logic_hash = "45820e0398cca8e75fc4acf6863d962a817afd95a4592acd4ac4a50029684220"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "copy ( $dosya_gonder"

	condition:
		all of them
}
