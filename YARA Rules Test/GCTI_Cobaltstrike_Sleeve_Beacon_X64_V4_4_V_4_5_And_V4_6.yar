rule GCTI_Cobaltstrike_Sleeve_Beacon_X64_V4_4_V_4_5_And_V4_6
{
	meta:
		description = "Cobalt Strike's sleeve/beacon.x64.dll Versions 4.4 through at least 4.6"
		author = "gssincla@google.com"
		id = "79b6bfd4-1e45-5bd9-ac5c-19eb176ce698"
		date = "2022-11-18"
		modified = "2023-12-04"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		source_url = "https://github.com/chronicle/GCTI/blob/1c5fd42b1895098527fde00c2d9757edf6b303bb/YARA/CobaltStrike/CobaltStrike__Resources_Beacon_Dll_All_Versions_MemEnabled.yara#L1593-L1628"
		license_url = "https://github.com/chronicle/GCTI/blob/1c5fd42b1895098527fde00c2d9757edf6b303bb/LICENSE"
		hash = "3280fec57b7ca94fd2bdb5a4ea1c7e648f565ac077152c5a81469030ccf6ab44"
		logic_hash = "be0bbf58a176f8089924b3ce58268d906f49dde51d863524971e46f4bada43a3"
		score = 75
		quality = 85
		tags = ""

	strings:
		$version_sig = { 8B D0 49 8B CA 48 83 C4 28 E9 83 88 FF FF
                     4C 8D 05 A4 6D FF FF 8B D0 49 8B CA 48 83 C4 28 }
		$decoder = { 80 34 28 ?? 48 FF C0 48 3D 00 10 00 00 7C F1 }

	condition:
		all of them
}