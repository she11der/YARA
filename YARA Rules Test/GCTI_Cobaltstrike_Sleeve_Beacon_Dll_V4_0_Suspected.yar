rule GCTI_Cobaltstrike_Sleeve_Beacon_Dll_V4_0_Suspected
{
	meta:
		description = "Cobalt Strike's sleeve/beacon.dll Versions 4.0 (suspected, not confirmed)"
		author = "gssincla@google.com"
		id = "50ff6e44-ebc0-5000-a816-b385a6675768"
		date = "2022-11-18"
		modified = "2023-12-04"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		source_url = "https://github.com/chronicle/GCTI/blob/1c5fd42b1895098527fde00c2d9757edf6b303bb/YARA/CobaltStrike/CobaltStrike__Resources_Beacon_Dll_All_Versions_MemEnabled.yara#L868-L901"
		license_url = "https://github.com/chronicle/GCTI/blob/1c5fd42b1895098527fde00c2d9757edf6b303bb/LICENSE"
		hash = "e2b2b72454776531bbc6a4a5dd579404250901557f887a6bccaee287ac71b248"
		logic_hash = "6875099bc6df26f829f9f64e70bd7fdac6ac7b83a5596fc9359c127fef4e6db5"
		score = 75
		quality = 85
		tags = ""

	strings:
		$version_sig = { 51 4A 56 57 83 FA 62 0F 87 8F 03 00 00 FF 24 95 56 7B 00 10 }
		$decoder = { 80 B0 [4] ?? 40 3D 00 10 00 00 7C F1 }

	condition:
		all of them
}