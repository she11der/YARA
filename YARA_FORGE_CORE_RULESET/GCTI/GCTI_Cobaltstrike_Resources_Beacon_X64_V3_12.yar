rule GCTI_Cobaltstrike_Resources_Beacon_X64_V3_12
{
	meta:
		description = "Cobalt Strike's sleeve/beacon.x64.dll Versions 3.12"
		author = "gssincla@google.com"
		id = "6eeae9f4-96e0-5a98-a8dc-779c916cd968"
		date = "2022-11-18"
		modified = "2023-12-04"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		source_url = "https://github.com/chronicle/GCTI/blob/1c5fd42b1895098527fde00c2d9757edf6b303bb/YARA/CobaltStrike/CobaltStrike__Resources_Beacon_Dll_All_Versions_MemEnabled.yara#L1368-L1404"
		license_url = "https://github.com/chronicle/GCTI/blob/1c5fd42b1895098527fde00c2d9757edf6b303bb/LICENSE"
		hash = "8a28b7a7e32ace2c52c582d0076939d4f10f41f4e5fa82551e7cc8bdbcd77ebc"
		logic_hash = "7457b20f2a7dc7e8c3317cedbcfccae30ecc8dc164188c0321f9485fdfab0f6e"
		score = 75
		quality = 85
		tags = ""

	strings:
		$version_sig = { 8B D3 48 8B CF E8 F8 2E 00 00 EB 16 8B D3 48 8B CF
                     E8 00 5C 00 00 EB 0A 8B D3 48 8B CF E8 64 4F 00 00 }
		$decoder = { 80 34 28 ?? 48 FF C0 48 3D 00 10 00 00 7C F1 }

	condition:
		all of them
}
