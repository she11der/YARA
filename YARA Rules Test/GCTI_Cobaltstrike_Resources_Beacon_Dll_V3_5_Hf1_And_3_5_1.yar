rule GCTI_Cobaltstrike_Resources_Beacon_Dll_V3_5_Hf1_And_3_5_1
{
	meta:
		description = "Cobalt Strike's resources/beacon.dll Versions 3.5-hf1 and 3.5.1 (3.5.x)"
		author = "gssincla@google.com"
		id = "1532596e-be0e-58c2-8d3b-5120c793d677"
		date = "2022-11-18"
		modified = "2023-12-04"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		source_url = "https://github.com/chronicle/GCTI/blob/1c5fd42b1895098527fde00c2d9757edf6b303bb/YARA/CobaltStrike/CobaltStrike__Resources_Beacon_Dll_All_Versions_MemEnabled.yara#L594-L625"
		license_url = "https://github.com/chronicle/GCTI/blob/1c5fd42b1895098527fde00c2d9757edf6b303bb/LICENSE"
		hash = "c78e70cd74f4acda7d1d0bd85854ccacec79983565425e98c16a9871f1950525"
		logic_hash = "c2e975678815638803b04261d46bca216bc0b2f894a1f72fd0d5b949493401d1"
		score = 75
		quality = 85
		tags = ""

	strings:
		$version_sig = { 48 57 8B F1 83 F8 43 0F 87 07 03 00 00 FF 24 }
		$decoder = { 80 B0 [4] ?? 40 3D 00 10 00 00 7C F1 }

	condition:
		all of them
}