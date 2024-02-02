rule GCTI_Cobaltstrike_Resources_Beacon_X64_V3_3
{
	meta:
		description = "Cobalt Strike's sleeve/beacon.x64.dll Versions 3.3"
		author = "gssincla@google.com"
		id = "fb96ecff-809e-5704-974e-a2d8ef022daa"
		date = "2022-11-18"
		modified = "2023-12-04"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		source_url = "https://github.com/chronicle/GCTI/blob/1c5fd42b1895098527fde00c2d9757edf6b303bb/YARA/CobaltStrike/CobaltStrike__Resources_Beacon_Dll_All_Versions_MemEnabled.yara#L1070-L1109"
		license_url = "https://github.com/chronicle/GCTI/blob/1c5fd42b1895098527fde00c2d9757edf6b303bb/LICENSE"
		hash = "7b00721efeff6ed94ab108477d57b03022692e288cc5814feb5e9d83e3788580"
		logic_hash = "514d491b8066ed7127ebb152a27efbe65e1121da3b5460afe6987920a91f2863"
		score = 75
		quality = 85
		tags = ""

	strings:
		$version_sig = { 8B D3 48 8B CF E8 89 66 00 00 E9 23 FB FF FF 
                     41 B8 01 00 00 00 E9 F3 FD FF FF 48 8D 0D 2A F8 FF FF
                     E8 8D 2B 00 00 48 8B 5C 24 30 48 83 C4 20 }
		$decoder = { 80 31 ?? FF C2 48 FF C1 48 63 C2 48 3D 10 06 00 00 }

	condition:
		all of them
}