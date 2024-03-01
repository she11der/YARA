rule GCTI_Cobaltstrike_Resources_Beacon_X64_V3_13
{
	meta:
		description = "Cobalt Strike's sleeve/beacon.x64.dll Versions 3.13"
		author = "gssincla@google.com"
		id = "202eb8ea-7afb-515b-9306-67514abf5e55"
		date = "2022-11-18"
		modified = "2023-12-04"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		source_url = "https://github.com/chronicle/GCTI/blob/1c5fd42b1895098527fde00c2d9757edf6b303bb/YARA/CobaltStrike/CobaltStrike__Resources_Beacon_Dll_All_Versions_MemEnabled.yara#L1407-L1440"
		license_url = "https://github.com/chronicle/GCTI/blob/1c5fd42b1895098527fde00c2d9757edf6b303bb/LICENSE"
		hash = "945e10dcd57ba23763481981c6035e0d0427f1d3ba71e75decd94b93f050538e"
		logic_hash = "81571a6c30802430d0df9980e005736d58464bde98c0889b48bf8d0c7e88d247"
		score = 75
		quality = 85
		tags = ""

	strings:
		$version_sig = { 48 8D 0D 01 5B FF FF 48 83 C4 28 E9 A8 54 FF FF 8B D0
                     49 8B CA E8 22 55 FF FF }
		$decoder = { 80 34 28 ?? 48 FF C0 48 3D 00 10 00 00 7C F1 }

	condition:
		all of them
}
