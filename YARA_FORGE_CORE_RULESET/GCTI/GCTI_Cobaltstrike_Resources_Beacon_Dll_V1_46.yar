rule GCTI_Cobaltstrike_Resources_Beacon_Dll_V1_46
{
	meta:
		description = "Cobalt Strike's resources/beacon.dll Version 1.46"
		author = "gssincla@google.com"
		id = "79715042-1963-5e48-8b64-7d915da58d84"
		date = "2022-11-18"
		modified = "2023-12-04"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		source_url = "https://github.com/chronicle/GCTI/blob/1c5fd42b1895098527fde00c2d9757edf6b303bb/YARA/CobaltStrike/CobaltStrike__Resources_Beacon_Dll_All_Versions_MemEnabled.yara#L86-L115"
		license_url = "https://github.com/chronicle/GCTI/blob/1c5fd42b1895098527fde00c2d9757edf6b303bb/LICENSE"
		hash = "44e34f4024878024d4804246f57a2b819020c88ba7de160415be38cd6b5e2f76"
		logic_hash = "1a5c63c8b5527c0442830a73ded8458cf82a9d8ecb9b31e9a02c10b27ed6195e"
		score = 75
		quality = 85
		tags = ""

	strings:
		$version_sig = { 8B F2 83 F9 0C 0F 87 8E 00 00 00 FF 24 }
		$decode = { B1 ?? 30 88 [4] 40 3D A8 01 00 00 7C F2 }

	condition:
		all of them
}
