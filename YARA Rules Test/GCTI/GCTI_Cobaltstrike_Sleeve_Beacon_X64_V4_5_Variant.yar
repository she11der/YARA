rule GCTI_Cobaltstrike_Sleeve_Beacon_X64_V4_5_Variant
{
	meta:
		description = "Cobalt Strike's sleeve/beacon.x64.dll Versions 4.5 (variant)"
		author = "gssincla@google.com"
		id = "45715da9-8f16-5304-b216-1ca36c508c77"
		date = "2022-11-18"
		modified = "2023-12-04"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		source_url = "https://github.com/chronicle/GCTI/blob/1c5fd42b1895098527fde00c2d9757edf6b303bb/YARA/CobaltStrike/CobaltStrike__Resources_Beacon_Dll_All_Versions_MemEnabled.yara#L1630-L1665"
		license_url = "https://github.com/chronicle/GCTI/blob/1c5fd42b1895098527fde00c2d9757edf6b303bb/LICENSE"
		hash = "8f0da7a45945b630cd0dfb5661036e365dcdccd085bc6cff2abeec6f4c9f1035"
		logic_hash = "31a108168489a24d1bc297d722741f3fd19abd1bed4c76d54967c73986d18123"
		score = 75
		quality = 85
		tags = ""

	strings:
		$version_sig = { 41 B8 01 00 00 00 8B D0 49 8B CA 48 83 C4 28 E9 E8 AB FF FF
                     8B D0 49 8B CA E8 1A EB FF FF 48 83 C4 28 }
		$decoder = { 80 34 28 ?? 48 FF C0 48 3D 00 10 00 00 7C F1 }

	condition:
		all of them
}