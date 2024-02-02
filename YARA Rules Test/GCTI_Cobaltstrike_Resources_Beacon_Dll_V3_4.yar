rule GCTI_Cobaltstrike_Resources_Beacon_Dll_V3_4
{
	meta:
		description = "Cobalt Strike's resources/beacon.dll Versions 3.4"
		author = "gssincla@google.com"
		id = "58a34ab6-c061-59a2-b929-8519d3d844e7"
		date = "2022-11-18"
		modified = "2023-12-04"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		source_url = "https://github.com/chronicle/GCTI/blob/1c5fd42b1895098527fde00c2d9757edf6b303bb/YARA/CobaltStrike/CobaltStrike__Resources_Beacon_Dll_All_Versions_MemEnabled.yara#L562-L592"
		license_url = "https://github.com/chronicle/GCTI/blob/1c5fd42b1895098527fde00c2d9757edf6b303bb/LICENSE"
		hash = "5c40bfa04a957d68a095dd33431df883e3a075f5b7dea3e0be9834ce6d92daa3"
		logic_hash = "f3372bc538092e30c62d9599f76f2115dc73faf7a5fd6f86c8d4cfaa35473810"
		score = 75
		quality = 85
		tags = ""

	strings:
		$version_sig = { 48 57 8B F1 83 F8 42 0F 87 F0 02 00 00 FF 24 }
		$decoder = { 80 B0 [4] ?? 40 3D 00 10 00 00 7C F1 }

	condition:
		all of them
}