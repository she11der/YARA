rule GCTI_Cobaltstrike_Resources_Beacon_Dll_V3_11_Bugfix_And_V3_12
{
	meta:
		description = "Cobalt Strike's resources/beacon.dll Versions 3.11-bugfix and 3.12"
		author = "gssincla@google.com"
		id = "08ff2a2f-97bd-5839-b414-d67fbf2cdb0f"
		date = "2022-11-18"
		modified = "2023-12-04"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		source_url = "https://github.com/chronicle/GCTI/blob/1c5fd42b1895098527fde00c2d9757edf6b303bb/YARA/CobaltStrike/CobaltStrike__Resources_Beacon_Dll_All_Versions_MemEnabled.yara#L772-L804"
		license_url = "https://github.com/chronicle/GCTI/blob/1c5fd42b1895098527fde00c2d9757edf6b303bb/LICENSE"
		hash = "5912c96fffeabb2c5c5cdd4387cfbfafad5f2e995f310ace76ca3643b866e3aa"
		logic_hash = "566eb14f918ad422d5a273390263e63ac37b00cd10ac3561e038fb1a27f85d80"
		score = 75
		quality = 85
		tags = ""
		rs2 = "4476a93abe48b7481c7b13dc912090b9476a2cdf46a1c4287b253098e3523192"

	strings:
		$version_sig = { 48 57 8B FA 83 F8 50 0F 87 0D 03 00 00 FF 24 }
		$decoder = { 80 B0 [4] ?? 40 3D 00 10 00 00 7C F1 }

	condition:
		all of them
}
