rule GCTI_Cobaltstrike_Resources_Beacon_Dll_V2_0_49
{
	meta:
		description = "Cobalt Strike's resources/beacon.dll Version 2.0.49"
		author = "gssincla@google.com"
		id = "087c584a-5ceb-536a-8842-53fbd668df54"
		date = "2022-11-18"
		modified = "2023-12-04"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		source_url = "https://github.com/chronicle/GCTI/blob/1c5fd42b1895098527fde00c2d9757edf6b303bb/YARA/CobaltStrike/CobaltStrike__Resources_Beacon_Dll_All_Versions_MemEnabled.yara#L213-L243"
		license_url = "https://github.com/chronicle/GCTI/blob/1c5fd42b1895098527fde00c2d9757edf6b303bb/LICENSE"
		hash = "ed08c1a21906e313f619adaa0a6e5eb8120cddd17d0084a30ada306f2aca3a4e"
		logic_hash = "3616579dabcfd0ba413d17b4fbd0da5313b9beca94f7bf8e41f05d6679b4a215"
		score = 75
		quality = 85
		tags = ""

	strings:
		$version_sig = { 83 F8 22 0F 87 96 01 00 00 FF 24 }
		$decoder = { B1 ?? EB 03 8D 49 00 30 88 [4] 40 3D 30 05 00 00 72 F2  }

	condition:
		all of them
}
