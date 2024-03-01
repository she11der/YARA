rule GCTI_Cobaltstrike_Resources_Beacon_Dll_V3_6
{
	meta:
		description = "Cobalt Strike's resources/beacon.dll Versions 3.6"
		author = "gssincla@google.com"
		id = "7e7b5c22-82b3-5298-b794-b06d94a668d5"
		date = "2022-11-18"
		modified = "2023-12-04"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		source_url = "https://github.com/chronicle/GCTI/blob/1c5fd42b1895098527fde00c2d9757edf6b303bb/YARA/CobaltStrike/CobaltStrike__Resources_Beacon_Dll_All_Versions_MemEnabled.yara#L627-L657"
		license_url = "https://github.com/chronicle/GCTI/blob/1c5fd42b1895098527fde00c2d9757edf6b303bb/LICENSE"
		hash = "495a744d0a0b5f08479c53739d08bfbd1f3b9818d8a9cbc75e71fcda6c30207d"
		logic_hash = "3bd3f0b8625e131726fa92d68de041dae6c3d5642cbf22ac596d1d82da1d4a07"
		score = 75
		quality = 85
		tags = ""

	strings:
		$version_sig = { 48 57 8B F9 83 F8 47 0F 87 2F 03 00 00 FF 24 }
		$decoder = { 80 B0 [4] ?? 40 3D 00 10 00 00 7C F1 }

	condition:
		all of them
}
