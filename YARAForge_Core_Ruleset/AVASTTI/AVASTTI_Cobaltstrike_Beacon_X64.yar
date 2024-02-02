rule AVASTTI_Cobaltstrike_Beacon_X64
{
	meta:
		description = "No description has been set in the source file - AvastTI"
		author = "Avast Threat Intel Team"
		id = "5d6d86ec-9e05-5596-b623-30f44c6f44db"
		date = "2021-07-08"
		modified = "2021-07-08"
		reference = "https://github.com/avast/ioc"
		source_url = "https://github.com/avast/ioc/blob/b515ef8c40e107f0cb519789bc1c5be5bdcb9d6b/CobaltStrike/yara_rules/cs_rules.yar#L634-L651"
		license_url = "N/A"
		logic_hash = "7abf5f9a337c60944a52efcc7a16a768652c46843d2da3df2f946dd6e63f9375"
		score = 75
		quality = 90
		tags = ""

	strings:
		$h01 = { 4D 5A 41 52 55 48 89 E5 48 81 EC 20 00 00 00 48 8D 1D EA FF FF FF 48 89 }
		$h11 = { 00 01 00 01 00 02 ?? ?? 00 02 00 01 00 02 ?? ?? 00 }
		$h12 = { 69 68 69 68 69 6B ?? ?? 69 6B 69 68 69 6B ?? ?? 69 }
		$h13 = { 2E 2F 2E 2F 2E 2C ?? ?? 2E 2C 2E 2F 2E 2C ?? ?? 2E }

	condition:
		$h01 and any of ($h1*)
}