rule GCTI_Cobaltstrike_Resources_Beacon_Dll_V2_1_And_V2_2
{
	meta:
		description = "Cobalt Strike's resources/beacon.dll Versions 2.1 and 2.2"
		author = "gssincla@google.com"
		id = "384fb247-aae7-52e1-a45d-6bda0f80a04e"
		date = "2022-11-18"
		modified = "2023-12-04"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		source_url = "https://github.com/chronicle/GCTI/blob/1c5fd42b1895098527fde00c2d9757edf6b303bb/YARA/CobaltStrike/CobaltStrike__Resources_Beacon_Dll_All_Versions_MemEnabled.yara#L245-L276"
		license_url = "https://github.com/chronicle/GCTI/blob/1c5fd42b1895098527fde00c2d9757edf6b303bb/LICENSE"
		hash = "ae7a1d12e98b8c9090abe19bcaddbde8db7b119c73f7b40e76cdebb2610afdc2"
		logic_hash = "eee3702d6fde08b8e9f5533f903fa33fb3da808a3b76ca43e4d5029f9ce91ad0"
		score = 75
		quality = 85
		tags = ""

	strings:
		$version_sig = { 49 56 57 83 F9 24 0F 87 8A 01 00 00 FF 24 }
		$decoder = { 80 B0 [4] ?? 40 3D 10 06 00 00 72 F1 }

	condition:
		all of them
}