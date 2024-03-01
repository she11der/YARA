rule DITEKSHEN_INDICATOR_KB_ID_Ransomware_Spyro
{
	meta:
		description = "Detects files referencing identities associated with Spyro ransomware"
		author = "ditekShen"
		id = "9a42a9fd-dfaf-5719-acae-e7c3b92ecdc9"
		date = "2024-01-23"
		modified = "2024-01-23"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_id.yar#L301-L310"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "b12b24b7b1b9800d249fd322532d957ddfc020c495ca89414d8d7e9fa7d58eb7"
		score = 75
		quality = 71
		tags = ""

	strings:
		$s1 = "blackspyro@tutanota.com" ascii wide nocase
		$s2 = "blackspyro@mailfence.com" ascii wide nocase

	condition:
		any of them
}
