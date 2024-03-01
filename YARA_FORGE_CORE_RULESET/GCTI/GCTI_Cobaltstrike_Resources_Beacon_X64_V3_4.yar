rule GCTI_Cobaltstrike_Resources_Beacon_X64_V3_4
{
	meta:
		description = "Cobalt Strike's sleeve/beacon.x64.dll Versions 3.4"
		author = "gssincla@google.com"
		id = "97ef152c-86c7-513c-a881-e7d594d38dcf"
		date = "2022-11-18"
		modified = "2023-12-04"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		source_url = "https://github.com/chronicle/GCTI/blob/1c5fd42b1895098527fde00c2d9757edf6b303bb/YARA/CobaltStrike/CobaltStrike__Resources_Beacon_Dll_All_Versions_MemEnabled.yara#L1111-L1148"
		license_url = "https://github.com/chronicle/GCTI/blob/1c5fd42b1895098527fde00c2d9757edf6b303bb/LICENSE"
		hash = "5a4d48c2eda8cda79dc130f8306699c8203e026533ce5691bf90363473733bf0"
		logic_hash = "65aa42265133038f6f568c021c0228440e84e236829af50796a73f6923f46395"
		score = 75
		quality = 85
		tags = ""

	strings:
		$version_sig = { 8B D3 48 8B CF E8 56 6F 00 00 E9 17 FB FF FF
                     41 B8 01 00 00 00 8B D3 48 8B CF E8 41 4D 00 00
                     48 8B 5C 24 30 48 83 C4 20 }
		$decoder = { 80 34 28 ?? 48 FF C0 48 3D 00 10 00 00 7C F1 }

	condition:
		all of them
}
