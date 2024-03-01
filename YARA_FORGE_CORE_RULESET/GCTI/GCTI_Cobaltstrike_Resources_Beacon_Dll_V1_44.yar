rule GCTI_Cobaltstrike_Resources_Beacon_Dll_V1_44
{
	meta:
		description = "Cobalt Strike's resources/beacon.dll Version 1.44"
		author = "gssincla@google.com"
		id = "935ee27f-ce1b-5491-b4a3-cb78f199ab1b"
		date = "2022-11-18"
		modified = "2023-12-04"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		source_url = "https://github.com/chronicle/GCTI/blob/1c5fd42b1895098527fde00c2d9757edf6b303bb/YARA/CobaltStrike/CobaltStrike__Resources_Beacon_Dll_All_Versions_MemEnabled.yara#L17-L49"
		license_url = "https://github.com/chronicle/GCTI/blob/1c5fd42b1895098527fde00c2d9757edf6b303bb/LICENSE"
		hash = "75102e8041c58768477f5f982500da7e03498643b6ece86194f4b3396215f9c2"
		logic_hash = "ebed8b6dc0b929164b1aa25b491b9d2fbb61d380a8b1268df7d424afe90f613d"
		score = 75
		quality = 85
		tags = ""

	strings:
		$version_sig = { 0F B7 D2 4A 53 8B D9 83 FA 04 77 36 FF 24 }
		$decode = { B1 ?? 30 88 [4] 40 3D 28 01 00 00 7C F2 }

	condition:
		all of them
}
