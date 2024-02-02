rule GCTI_Cobaltstrike_Resources_Beacon_Dll_V3_3
{
	meta:
		description = "Cobalt Strike's resources/beacon.dll Versions 3.3"
		author = "gssincla@google.com"
		id = "7cce26c9-1403-535f-bd9d-19667c7e313c"
		date = "2022-11-18"
		modified = "2023-12-04"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		source_url = "https://github.com/chronicle/GCTI/blob/1c5fd42b1895098527fde00c2d9757edf6b303bb/YARA/CobaltStrike/CobaltStrike__Resources_Beacon_Dll_All_Versions_MemEnabled.yara#L530-L560"
		license_url = "https://github.com/chronicle/GCTI/blob/1c5fd42b1895098527fde00c2d9757edf6b303bb/LICENSE"
		hash = "158dba14099f847816e2fc22f254c60e09ac999b6c6e2ba6f90c6dd6d937bc42"
		logic_hash = "f9b9b669aacc156a4e07eab0c6a638f9b9d828e018d1db89e9e2c922641744ac"
		score = 75
		quality = 85
		tags = ""

	strings:
		$version_sig = { 48 57 8B F1 83 F8 41 0F 87 F0 02 00 00 FF 24 }
		$decoder = { 80 B0 [4] ?? 40 3D 10 06 00 00 72 F1 }

	condition:
		all of them
}