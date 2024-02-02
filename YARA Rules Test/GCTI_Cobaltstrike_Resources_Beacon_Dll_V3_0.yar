rule GCTI_Cobaltstrike_Resources_Beacon_Dll_V3_0
{
	meta:
		description = "Cobalt Strike's resources/beacon.dll Versions 3.0"
		author = "gssincla@google.com"
		id = "132a1be8-f529-5141-ba03-fdf6df3d55d4"
		date = "2022-11-18"
		modified = "2023-12-04"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		source_url = "https://github.com/chronicle/GCTI/blob/1c5fd42b1895098527fde00c2d9757edf6b303bb/YARA/CobaltStrike/CobaltStrike__Resources_Beacon_Dll_All_Versions_MemEnabled.yara#L374-L404"
		license_url = "https://github.com/chronicle/GCTI/blob/1c5fd42b1895098527fde00c2d9757edf6b303bb/LICENSE"
		hash = "30251f22df7f1be8bc75390a2f208b7514647835f07593f25e470342fd2e3f52"
		logic_hash = "951f1b52c14010261022f9f920d53d3c1e88f41461798a23e72083c981f9de76"
		score = 75
		quality = 85
		tags = ""

	strings:
		$version_sig = { 48 57 8B F2 83 F8 3C 0F 87 89 02 00 00 FF 24 }
		$decoder = { 80 B0 [4] ?? 40 3D 10 06 00 00 72 F1 }

	condition:
		all of them
}