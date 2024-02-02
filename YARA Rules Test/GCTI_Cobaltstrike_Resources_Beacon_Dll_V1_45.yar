rule GCTI_Cobaltstrike_Resources_Beacon_Dll_V1_45
{
	meta:
		description = "Cobalt Strike's resources/beacon.dll Version 1.45"
		author = "gssincla@google.com"
		id = "04d4d0ee-f1ee-5888-8108-ca55243c770a"
		date = "2022-11-18"
		modified = "2023-12-04"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		source_url = "https://github.com/chronicle/GCTI/blob/1c5fd42b1895098527fde00c2d9757edf6b303bb/YARA/CobaltStrike/CobaltStrike__Resources_Beacon_Dll_All_Versions_MemEnabled.yara#L51-L84"
		license_url = "https://github.com/chronicle/GCTI/blob/1c5fd42b1895098527fde00c2d9757edf6b303bb/LICENSE"
		hash = "1a92b2024320f581232f2ba1e9a11bef082d5e9723429b3e4febb149458d1bb1"
		logic_hash = "b1472907e0fe0cb26219c268f23483681cc076dab96c1b0f2f0ee472ad319b4f"
		score = 75
		quality = 85
		tags = ""

	strings:
		$version_sig = { 51 0F B7 D2 4A 53 56 83 FA 08 77 6B FF 24 }
		$decode = { B1 ?? 30 88 [4] 40 3D 28 01 00 00 7C F2 }

	condition:
		all of them
}