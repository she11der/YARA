rule GCTI_Cobaltstrike_Resources_Beacon_X64_V3_11
{
	meta:
		description = "Cobalt Strike's sleeve/beacon.x64.dll Versions 3.11 (two subversions)"
		author = "gssincla@google.com"
		id = "bf0c7661-2583-5fca-beb5-abb2b50c860d"
		date = "2022-11-18"
		modified = "2023-12-04"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		source_url = "https://github.com/chronicle/GCTI/blob/1c5fd42b1895098527fde00c2d9757edf6b303bb/YARA/CobaltStrike/CobaltStrike__Resources_Beacon_Dll_All_Versions_MemEnabled.yara#L1312-L1366"
		license_url = "https://github.com/chronicle/GCTI/blob/1c5fd42b1895098527fde00c2d9757edf6b303bb/LICENSE"
		hash = "64007e104dddb6b5d5153399d850f1e1f1720d222bed19a26d0b1c500a675b1a"
		logic_hash = "9c34b23b659463a0ab92949031a9b3246aa95256d1548b2f0ad53fe3d379997d"
		score = 75
		quality = 85
		tags = ""
		rs2 = "815f313e0835e7fdf4a6d93f2774cf642012fd21ce870c48ff489555012e0047"

	strings:
		$version_sig = { 48 83 EC 20 41 8B D8 48 8B FA 83 F9 2D 0F 87 B2 03 00 00
                     0F 84 90 03 00 00 83 F9 17 0F 87 F8 01 00 00
                     0F 84 DC 01 00 00 83 F9 0E 0F 87 F9 00 00 00
                     0F 84 DD 00 00 00 FF C9 0F 84 C0 00 00 00 83 E9 02
                     0F 84 A6 00 00 00 FF C9 }
		$decoder = {
      80 34 28 ?? 
      48 FF C0
      48 3D 00 10 00 00
      7C F1
    }

	condition:
		all of them
}