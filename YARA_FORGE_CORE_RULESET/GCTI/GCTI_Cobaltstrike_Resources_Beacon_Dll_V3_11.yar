rule GCTI_Cobaltstrike_Resources_Beacon_Dll_V3_11
{
	meta:
		description = "Cobalt Strike's resources/beacon.dll Versions 3.11"
		author = "gssincla@google.com"
		id = "00e42396-db81-5d43-90ee-5a97b379019e"
		date = "2022-11-18"
		modified = "2023-12-04"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		source_url = "https://github.com/chronicle/GCTI/blob/1c5fd42b1895098527fde00c2d9757edf6b303bb/YARA/CobaltStrike/CobaltStrike__Resources_Beacon_Dll_All_Versions_MemEnabled.yara#L739-L770"
		license_url = "https://github.com/chronicle/GCTI/blob/1c5fd42b1895098527fde00c2d9757edf6b303bb/LICENSE"
		hash = "2428b93464585229fd234677627431cae09cfaeb1362fe4f648b8bee59d68f29"
		logic_hash = "24ca0a9c2249d1872a53dc228234bdc6803bdfe9e80847995e0951184a8d935c"
		score = 75
		quality = 85
		tags = ""

	strings:
		$version_sig = { 48 57 8B FA 83 F8 50 0F 87 11 03 00 00 FF 24 }
		$decoder = { 80 B0 [4] ?? 40 3D 00 10 00 00 7C F1 }

	condition:
		all of them
}
