rule GCTI_Cobaltstrike_Resources_Beacon_X64_V3_5_Hf1_And_V3_5_1
{
	meta:
		description = "Cobalt Strike's sleeve/beacon.x64.dll Versions 3.5-hf1 and 3.5.1"
		author = "gssincla@google.com"
		id = "0c0e87d3-e0e2-5ddc-9d89-5e56443da4b8"
		date = "2022-11-18"
		modified = "2023-12-04"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		source_url = "https://github.com/chronicle/GCTI/blob/1c5fd42b1895098527fde00c2d9757edf6b303bb/YARA/CobaltStrike/CobaltStrike__Resources_Beacon_Dll_All_Versions_MemEnabled.yara#L1150-L1189"
		license_url = "https://github.com/chronicle/GCTI/blob/1c5fd42b1895098527fde00c2d9757edf6b303bb/LICENSE"
		hash = "934134ab0ee65ec76ae98a9bb9ad0e9571d80f4bf1eb3491d58bacf06d42dc8d"
		logic_hash = "5cd69554edb91956f4ec4c3c5e55f4cd9c3665656c318220ba3a270c0bb0a690"
		score = 75
		quality = 85
		tags = ""

	strings:
		$version_sig = { 8B D3 48 8B CF E8 38 70 00 00 E9 FD FA FF FF 
                     41 B8 01 00 00 00 8B D3 48 8B CF E8 3F 4D 00 00 
                     48 8B 5C 24 30 48 83 C4 20 5F }
		$decoder = { 80 34 28 ?? 48 FF C0 48 3D 00 10 00 00 7C F1 }

	condition:
		all of them
}