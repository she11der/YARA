rule GCTI_Cobaltstrike_Resources_Beacon_Dll_V3_2
{
	meta:
		description = "Cobalt Strike's resources/beacon.dll Versions 3.2"
		author = "gssincla@google.com"
		id = "3ccbc0f2-241c-5c10-8930-4a3d264d3b57"
		date = "2022-11-18"
		modified = "2023-12-04"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		source_url = "https://github.com/chronicle/GCTI/blob/1c5fd42b1895098527fde00c2d9757edf6b303bb/YARA/CobaltStrike/CobaltStrike__Resources_Beacon_Dll_All_Versions_MemEnabled.yara#L463-L528"
		license_url = "https://github.com/chronicle/GCTI/blob/1c5fd42b1895098527fde00c2d9757edf6b303bb/LICENSE"
		hash = "b490eeb95d150530b8e155da5d7ef778543836a03cb5c27767f1ae4265449a8d"
		logic_hash = "e1fe0d58d86ad8c845d65608314007ce08e3e524fb92cdb33ddae860c640e3e9"
		score = 75
		quality = 85
		tags = ""
		rs2 = "a93647c373f16d61c38ba6382901f468247f12ba8cbe56663abb2a11ff2a5144"

	strings:
		$version_sig = { 48 57 8B F2 83 F8 3D 0F 87 83 02 00 00 FF 24 }
		$decoder = { 80 B0 [4] ?? 40 3D 10 06 00 00 72 F1 }
		$version3_1_sig = { 55 8B EC 83 EC 58 A1 [4] 33 C5 89 45 FC E8 DF F5 FF FF 6A 50 8D 45 A8 50 FF 15 [4] 8D 45 ?? 50 FF 15 [4] 85 C0 74 14 8B 40 0C 83 38 00 74 0C 8B 00 FF 30 FF 15 [4] EB 05 B8 [4] 8B 4D FC 33 CD E8 82 B7 00 00 C9 }

	condition:
		$version_sig and $decoder and not $version3_1_sig
}
