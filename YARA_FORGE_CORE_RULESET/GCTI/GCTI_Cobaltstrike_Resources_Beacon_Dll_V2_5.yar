rule GCTI_Cobaltstrike_Resources_Beacon_Dll_V2_5
{
	meta:
		description = "Cobalt Strike's resources/beacon.dll Versions 2.5"
		author = "gssincla@google.com"
		id = "a89f9239-099c-5b97-b1df-e8ce2b95ea52"
		date = "2022-11-18"
		modified = "2023-12-04"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		source_url = "https://github.com/chronicle/GCTI/blob/1c5fd42b1895098527fde00c2d9757edf6b303bb/YARA/CobaltStrike/CobaltStrike__Resources_Beacon_Dll_All_Versions_MemEnabled.yara#L342-L372"
		license_url = "https://github.com/chronicle/GCTI/blob/1c5fd42b1895098527fde00c2d9757edf6b303bb/LICENSE"
		hash = "d99693e3e521f42d19824955bef0cefb79b3a9dbf30f0d832180577674ee2b58"
		logic_hash = "f2d0ca1414a60bf855543d99777ae5e83c451db41aba5e255e4c10b1e0bb7b47"
		score = 75
		quality = 85
		tags = ""

	strings:
		$version_sig = { 48 57 8B F2 83 F8 3A 0F 87 6E 02 00 00 FF 24 }
		$decoder = { 80 B0 [4] ?? 40 3D 10 06 00 00 72 F1 }

	condition:
		all of them
}
