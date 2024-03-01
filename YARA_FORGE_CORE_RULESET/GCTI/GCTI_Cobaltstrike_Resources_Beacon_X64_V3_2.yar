rule GCTI_Cobaltstrike_Resources_Beacon_X64_V3_2
{
	meta:
		description = "Cobalt Strike's sleeve/beacon.x64.dll Versions 3.2"
		author = "gssincla@google.com"
		id = "61188243-0b90-5bff-bcc8-50f10ed941f6"
		date = "2022-11-18"
		modified = "2023-12-04"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		source_url = "https://github.com/chronicle/GCTI/blob/1c5fd42b1895098527fde00c2d9757edf6b303bb/YARA/CobaltStrike/CobaltStrike__Resources_Beacon_Dll_All_Versions_MemEnabled.yara#L1029-L1068"
		license_url = "https://github.com/chronicle/GCTI/blob/1c5fd42b1895098527fde00c2d9757edf6b303bb/LICENSE"
		hash = "5993a027f301f37f3236551e6ded520e96872723a91042bfc54775dcb34c94a1"
		logic_hash = "3803aaac537aec0b188870177e510a3789a71c19be576569b59aa146b2ba62c5"
		score = 75
		quality = 85
		tags = ""

	strings:
		$version_sig = { 4C 8D 05 9F F8 FF FF 8B D3 48 8B CF E8 05 1A 00 00
                     EB 0A 8B D3 48 8B CF E8 41 21 00 00 48 8B 5C 24 30
                     48 83 C4 20 }
		$decoder = { 80 31 ?? FF C2 48 FF C1 48 63 C2 48 3D 10 06 00 00 }

	condition:
		all of them
}
