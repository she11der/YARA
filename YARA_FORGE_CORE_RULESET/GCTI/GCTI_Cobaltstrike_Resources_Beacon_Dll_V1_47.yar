rule GCTI_Cobaltstrike_Resources_Beacon_Dll_V1_47
{
	meta:
		description = "Cobalt Strike's resources/beacon.dll Version 1.47"
		author = "gssincla@google.com"
		id = "ac2249a9-210c-581f-8dd1-7619356dca7d"
		date = "2022-11-18"
		modified = "2023-12-04"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		source_url = "https://github.com/chronicle/GCTI/blob/1c5fd42b1895098527fde00c2d9757edf6b303bb/YARA/CobaltStrike/CobaltStrike__Resources_Beacon_Dll_All_Versions_MemEnabled.yara#L117-L144"
		license_url = "https://github.com/chronicle/GCTI/blob/1c5fd42b1895098527fde00c2d9757edf6b303bb/LICENSE"
		hash = "8ff6dc80581804391183303bb39fca2a5aba5fe13d81886ab21dbd183d536c8d"
		logic_hash = "8c463d3122f3f79ff5d9b88e3d4f5ed14e6c581edfdfafba8a0c596c494ac1b1"
		score = 75
		quality = 85
		tags = ""

	strings:
		$version_sig = { 83 F8 12 77 10 FF 24 }
		$decode = { B1 ?? 30 88 [4] 40 3D A8 01 00 00 }

	condition:
		all of them
}
