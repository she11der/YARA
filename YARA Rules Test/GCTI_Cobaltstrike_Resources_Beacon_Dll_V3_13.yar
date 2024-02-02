rule GCTI_Cobaltstrike_Resources_Beacon_Dll_V3_13
{
	meta:
		description = "Cobalt Strike's resources/beacon.dll Versions 3.13"
		author = "gssincla@google.com"
		id = "98dd32e6-9bb5-57b2-a5e5-1c74a0d1e6d3"
		date = "2022-11-18"
		modified = "2023-12-04"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		source_url = "https://github.com/chronicle/GCTI/blob/1c5fd42b1895098527fde00c2d9757edf6b303bb/YARA/CobaltStrike/CobaltStrike__Resources_Beacon_Dll_All_Versions_MemEnabled.yara#L806-L836"
		license_url = "https://github.com/chronicle/GCTI/blob/1c5fd42b1895098527fde00c2d9757edf6b303bb/LICENSE"
		hash = "362119e3bce42e91cba662ea80f1a7957a5c2b1e92075a28352542f31ac46a0c"
		logic_hash = "adafac8692ad676b0168b3e829bc7948db72953b95c79d483ae1a05f1d4f9b2b"
		score = 75
		quality = 85
		tags = ""

	strings:
		$version_sig = { 4A 56 57 83 FA 5A 0F 87 2D 03 00 00 FF 24 }
		$decoder = { 80 B0 [4] ?? 40 3D 00 10 00 00 7C F1 }

	condition:
		all of them
}