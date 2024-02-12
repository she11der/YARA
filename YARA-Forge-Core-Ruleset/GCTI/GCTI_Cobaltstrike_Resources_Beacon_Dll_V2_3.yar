rule GCTI_Cobaltstrike_Resources_Beacon_Dll_V2_3
{
	meta:
		description = "Cobalt Strike's resources/beacon.dll Versions 2.3"
		author = "gssincla@google.com"
		id = "aed092f1-fbb1-5efe-be8d-fb7c5aba1cde"
		date = "2022-11-18"
		modified = "2023-12-04"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		source_url = "https://github.com/chronicle/GCTI/blob/1c5fd42b1895098527fde00c2d9757edf6b303bb/YARA/CobaltStrike/CobaltStrike__Resources_Beacon_Dll_All_Versions_MemEnabled.yara#L278-L308"
		license_url = "https://github.com/chronicle/GCTI/blob/1c5fd42b1895098527fde00c2d9757edf6b303bb/LICENSE"
		hash = "00dd982cb9b37f6effb1a5a057b6571e533aac5e9e9ee39a399bb3637775ff83"
		logic_hash = "286d7ffa83634b82160788abaf1c5b319a09c4a1243af2401799f327be76ad75"
		score = 75
		quality = 85
		tags = ""

	strings:
		$version_sig = { 49 56 57 83 F9 26 0F 87 A9 01 00 00 FF 24 }
		$decoder = { 80 B0 [4] ?? 40 3D 10 06 00 00 72 F1 }

	condition:
		all of them
}