rule GCTI_Cobaltstrike_Resources_Beacon_Dll_V1_48
{
	meta:
		description = "Cobalt Strike's resources/beacon.dll Version 1.48"
		author = "gssincla@google.com"
		id = "dd15099f-ad19-58df-9ed4-ce66d7ee8540"
		date = "2022-11-18"
		modified = "2023-12-04"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		source_url = "https://github.com/chronicle/GCTI/blob/1c5fd42b1895098527fde00c2d9757edf6b303bb/YARA/CobaltStrike/CobaltStrike__Resources_Beacon_Dll_All_Versions_MemEnabled.yara#L146-L178"
		license_url = "https://github.com/chronicle/GCTI/blob/1c5fd42b1895098527fde00c2d9757edf6b303bb/LICENSE"
		hash = "dd4e445572cd5e32d7e9cc121e8de337e6f19ff07547e3f2c6b7fce7eafd15e4"
		logic_hash = "3f789eaf334c9bb3236d2834f38156aa92b22a5b674450977086378d195dd216"
		score = 75
		quality = 85
		tags = ""

	strings:
		$version_sig = { 48 57 8B F1 8B DA 83 F8 17 77 12 FF 24 }
		$decode = { B1 ?? 30 88 [4] 40 3D A8 01 00 00 7C F2 }

	condition:
		all of them
}