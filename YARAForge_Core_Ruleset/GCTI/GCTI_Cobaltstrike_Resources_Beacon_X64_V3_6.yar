rule GCTI_Cobaltstrike_Resources_Beacon_X64_V3_6
{
	meta:
		description = "Cobalt Strike's sleeve/beacon.x64.dll Versions 3.6"
		author = "gssincla@google.com"
		id = "9651a1ca-d8ea-5b0b-bcba-a850c2e07791"
		date = "2022-11-18"
		modified = "2023-12-04"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		source_url = "https://github.com/chronicle/GCTI/blob/1c5fd42b1895098527fde00c2d9757edf6b303bb/YARA/CobaltStrike/CobaltStrike__Resources_Beacon_Dll_All_Versions_MemEnabled.yara#L1191-L1233"
		license_url = "https://github.com/chronicle/GCTI/blob/1c5fd42b1895098527fde00c2d9757edf6b303bb/LICENSE"
		hash = "92b0a4aec6a493bcb1b72ce04dd477fd1af5effa0b88a9d8283f26266bb019a1"
		logic_hash = "d6aff186a01386992f004cb775d280f9b6e7e16d7ecee662d61e3485b0bc088b"
		score = 75
		quality = 85
		tags = ""

	strings:
		$version_sig = { 48 89 5C 24 08 57 48 83 EC 20 41 8B D8 48 8B FA 83 F9 27
                     0F 87 47 03 00 00 0F 84 30 03 00 00 83 F9 14
                     0F 87 A4 01 00 00 0F 84 7A 01 00 00 83 F9 0C
                     0F 87 C8 00 00 00 0F 84 B3 00 00 00 }
		$decoder = { 80 34 28 ?? 48 FF C0 48 3D 00 10 00 00 7C F1 }

	condition:
		all of them
}