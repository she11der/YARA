rule GCTI_Cobaltstrike_Resources_Beacon_Dll_V2_4
{
	meta:
		description = "Cobalt Strike's resources/beacon.dll Versions 2.4"
		author = "gssincla@google.com"
		id = "347a6b06-84a8-53ff-80a1-05fa1a48a412"
		date = "2022-11-18"
		modified = "2023-12-04"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		source_url = "https://github.com/chronicle/GCTI/blob/1c5fd42b1895098527fde00c2d9757edf6b303bb/YARA/CobaltStrike/CobaltStrike__Resources_Beacon_Dll_All_Versions_MemEnabled.yara#L310-L340"
		license_url = "https://github.com/chronicle/GCTI/blob/1c5fd42b1895098527fde00c2d9757edf6b303bb/LICENSE"
		hash = "78c6f3f2b80e6140c4038e9c2bcd523a1b205d27187e37dc039ede4cf560beed"
		logic_hash = "087ec6f585e90b84c00e746beb37cb8365cb7b4d07ebd0c48e3ba3d5df94dba2"
		score = 75
		quality = 85
		tags = ""

	strings:
		$version_sig = { 4A 56 57 83 FA 2F 0F 87 F9 01 00 00 FF 24 }
		$decoder = { 80 B0 [4] ?? 40 3D 10 06 00 00 72 F1 }

	condition:
		all of them
}
