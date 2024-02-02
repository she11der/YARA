rule GCTI_Cobaltstrike_Sleeve_Beacon_X64_V4_3
{
	meta:
		description = "Cobalt Strike's sleeve/beacon.x64.dll Version 4.3"
		author = "gssincla@google.com"
		id = "572616c7-d1ec-5aa1-b142-4f2edf73737f"
		date = "2022-11-18"
		modified = "2023-12-04"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		source_url = "https://github.com/chronicle/GCTI/blob/1c5fd42b1895098527fde00c2d9757edf6b303bb/YARA/CobaltStrike/CobaltStrike__Resources_Beacon_Dll_All_Versions_MemEnabled.yara#L1555-L1590"
		license_url = "https://github.com/chronicle/GCTI/blob/1c5fd42b1895098527fde00c2d9757edf6b303bb/LICENSE"
		hash = "3ac9c3525caa29981775bddec43d686c0e855271f23731c376ba48761c27fa3d"
		logic_hash = "0c8934e997583339145749a3167ac010d8c77b2ed878d2c999de68ec2a98101d"
		score = 75
		quality = 85
		tags = ""

	strings:
		$version_sig = { 8B D0 49 8B CA 48 83 C4 28 E9 D3 88 FF FF
                     4C 8D 05 84 6E FF FF 8B D0 49 8B CA 48 83 C4 28 }
		$decoder = { 80 34 28 ?? 48 FF C0 48 3D 00 10 00 00 7C F1 }

	condition:
		all of them
}