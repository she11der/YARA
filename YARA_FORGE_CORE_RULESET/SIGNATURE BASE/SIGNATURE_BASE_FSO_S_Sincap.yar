rule SIGNATURE_BASE_FSO_S_Sincap
{
	meta:
		description = "Webshells Auto-generated - file sincap.php"
		author = "Florian Roth (Nextron Systems)"
		id = "fcee20a3-e71b-5f69-ac67-8660fd270703"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/thor-webshells.yar#L7250-L7262"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		hash = "dc5c2c2392b84a1529abd92e98e9aa5b"
		logic_hash = "705030e93248f5ea6744f78bd7a1816aaa9772880059286b8d686e05b193d4a0"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "    <font color=\"#E5E5E5\" style=\"font-size: 8pt; font-weight: 700\" face=\"Arial\">"
		$s4 = "<body text=\"#008000\" bgcolor=\"#808080\" topmargin=\"0\" leftmargin=\"0\" rightmargin="

	condition:
		all of them
}
