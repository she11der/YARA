rule GCTI_Cobaltstrike_Resources_Beacon_Dll_V1_49
{
	meta:
		description = "Cobalt Strike's resources/beacon.dll Version 1.49"
		author = "gssincla@google.com"
		id = "871e28c9-b580-5a32-8529-2290ded1a1b6"
		date = "2022-11-18"
		modified = "2023-12-04"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		source_url = "https://github.com/chronicle/GCTI/blob/1c5fd42b1895098527fde00c2d9757edf6b303bb/YARA/CobaltStrike/CobaltStrike__Resources_Beacon_Dll_All_Versions_MemEnabled.yara#L180-L211"
		license_url = "https://github.com/chronicle/GCTI/blob/1c5fd42b1895098527fde00c2d9757edf6b303bb/LICENSE"
		hash = "52b4bd87e21ee0cbaaa0fc007fd3f894c5fc2c4bae5cbc2a37188de3c2c465fe"
		logic_hash = "935232d5ddccdc0401b4d911cdc73a48305347b495219c8c893615fe918f32f1"
		score = 75
		quality = 85
		tags = ""

	strings:
		$version_sig = { 48 56 83 F8 1E 0F 87 23 01 00 00 FF 24 }
		$decoder = { B1 ?? 90 30 88 [4] 40 3D A8 01 00 00 7C F2 }

	condition:
		all of them
}