rule GCTI_Cobaltstrike_Resources_Beacon_Dll_V3_7
{
	meta:
		description = "Cobalt Strike's resources/beacon.dll Versions 3.7"
		author = "gssincla@google.com"
		id = "6352a31c-34b8-5886-8e34-ef9221c22e6e"
		date = "2022-11-18"
		modified = "2023-12-04"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		source_url = "https://github.com/chronicle/GCTI/blob/1c5fd42b1895098527fde00c2d9757edf6b303bb/YARA/CobaltStrike/CobaltStrike__Resources_Beacon_Dll_All_Versions_MemEnabled.yara#L659-L689"
		license_url = "https://github.com/chronicle/GCTI/blob/1c5fd42b1895098527fde00c2d9757edf6b303bb/LICENSE"
		hash = "f18029e6b12158fb3993f4951dab2dc6e645bb805ae515d205a53a1ef41ca9b2"
		logic_hash = "6ceb2cec8402a4679bad42d367156c74e897af4188442fdebc70d6ce2dd78bd6"
		score = 75
		quality = 85
		tags = ""

	strings:
		$version_sig = { 48 57 8B F9 83 F8 49 0F 87 47 03 00 00 FF 24 }
		$decoder = { 80 B0 [4] ?? 40 3D 00 10 00 00 7C F1 }

	condition:
		all of them
}