rule GCTI_Cobaltstrike_Resources_Beacon_X64_V3_8
{
	meta:
		description = "Cobalt Strike's sleeve/beacon.x64.dll Versions 3.8"
		author = "gssincla@google.com"
		id = "89809d81-9a8b-5cf3-a251-689bf52e98e0"
		date = "2022-11-18"
		modified = "2023-12-04"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		source_url = "https://github.com/chronicle/GCTI/blob/1c5fd42b1895098527fde00c2d9757edf6b303bb/YARA/CobaltStrike/CobaltStrike__Resources_Beacon_Dll_All_Versions_MemEnabled.yara#L1276-L1310"
		license_url = "https://github.com/chronicle/GCTI/blob/1c5fd42b1895098527fde00c2d9757edf6b303bb/LICENSE"
		hash = "547d44669dba97a32cb9e95cfb8d3cd278e00599e6a11080df1a9d09226f33ae"
		logic_hash = "8845b71ce4401fd194eb88f04dbf1f313af8b4853da004e63261ca3158fcb1d4"
		score = 75
		quality = 85
		tags = ""

	strings:
		$version_sig = { 8B D3 48 8B CF E8 7A 52 00 00 EB 0D 45 33 C0 8B D3 48 8B CF
                     E8 8F 55 00 00 }
		$decoder = { 80 34 28 ?? 48 FF C0 48 3D 00 10 00 00 7C F1 }

	condition:
		all of them
}