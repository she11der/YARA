rule AVASTTI_Cobaltstrike_Beacon_X86
{
	meta:
		description = "No description has been set in the source file - AvastTI"
		author = "Avast Threat Intel Team"
		id = "6ffaafe6-2758-53e4-b5b8-6d8350baf428"
		date = "2021-07-08"
		modified = "2021-07-08"
		reference = "https://github.com/avast/ioc"
		source_url = "https://github.com/avast/ioc/blob/b515ef8c40e107f0cb519789bc1c5be5bdcb9d6b/CobaltStrike/yara_rules/cs_rules.yar#L615-L632"
		license_url = "N/A"
		logic_hash = "e6328aae5954ac8e3914e65603813ba4f11d97ff91d08a1398e1f71740879463"
		score = 75
		quality = 90
		tags = ""

	strings:
		$h01 = { 4D 5A E8 00 00 00 00 5B 89 DF 52 45 55 89 E5 81 C3 ?? ?? ?? ?? FF D3 68 }
		$h11 = { 00 01 00 01 00 02 ?? ?? 00 02 00 01 00 02 ?? ?? 00 }
		$h12 = { 69 68 69 68 69 6B ?? ?? 69 6B 69 68 69 6B ?? ?? 69 }
		$h13 = { 2E 2F 2E 2F 2E 2C ?? ?? 2E 2C 2E 2F 2E 2C ?? ?? 2E }

	condition:
		$h01 and any of ($h1*)
}
