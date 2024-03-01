rule GCTI_Cobaltstrike_Resources_Beacon_X64_V3_7
{
	meta:
		description = "Cobalt Strike's sleeve/beacon.x64.dll Versions 3.7"
		author = "gssincla@google.com"
		id = "27fad98a-2882-5c52-af6e-c7dcf5559624"
		date = "2022-11-18"
		modified = "2023-12-04"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		source_url = "https://github.com/chronicle/GCTI/blob/1c5fd42b1895098527fde00c2d9757edf6b303bb/YARA/CobaltStrike/CobaltStrike__Resources_Beacon_Dll_All_Versions_MemEnabled.yara#L1235-L1274"
		license_url = "https://github.com/chronicle/GCTI/blob/1c5fd42b1895098527fde00c2d9757edf6b303bb/LICENSE"
		hash = "81296a65a24c0f6f22208b0d29e7bb803569746ce562e2fa0d623183a8bcca60"
		logic_hash = "89499e01acd607b2fbcdd134c74ca4a901c00c7c9cf70dd241cc538c1c0d083a"
		score = 75
		quality = 85
		tags = ""

	strings:
		$version_sig = { 48 89 5C 24 08 57 48 83 EC 20 41 8B D8 48 8B FA 83 F9 28
                     0F 87 7F 03 00 00 0F 84 67 03 00 00 83 F9 15
                     0F 87 DB 01 00 00 0F 84 BF 01 00 00 }
		$decoder = { 80 34 28 ?? 48 FF C0 48 3D 00 10 00 00 7C F1 }

	condition:
		all of them
}
