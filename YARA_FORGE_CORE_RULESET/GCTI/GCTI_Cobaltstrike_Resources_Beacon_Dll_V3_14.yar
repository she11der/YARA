rule GCTI_Cobaltstrike_Resources_Beacon_Dll_V3_14
{
	meta:
		description = "Cobalt Strike's resources/beacon.dll Versions 3.14"
		author = "gssincla@google.com"
		id = "00edfc72-c7b8-5100-8275-ae3548b96e49"
		date = "2022-11-18"
		modified = "2023-12-04"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		source_url = "https://github.com/chronicle/GCTI/blob/1c5fd42b1895098527fde00c2d9757edf6b303bb/YARA/CobaltStrike/CobaltStrike__Resources_Beacon_Dll_All_Versions_MemEnabled.yara#L838-L866"
		license_url = "https://github.com/chronicle/GCTI/blob/1c5fd42b1895098527fde00c2d9757edf6b303bb/LICENSE"
		hash = "254c68a92a7108e8c411c7b5b87a2f14654cd9f1324b344f036f6d3b6c7accda"
		logic_hash = "6faed2b69647b87d86d46ae73ad92cfe7b2746c306cd7480dc9f0c484c8882e2"
		score = 75
		quality = 85
		tags = ""
		rs2 = "87b3eb55a346b52fb42b140c03ac93fc82f5a7f80697801d3f05aea1ad236730"

	strings:
		$version_sig = { 83 FA 5B 77 15 FF 24 }
		$decoder = { 80 B0 [4] ?? 40 3D 00 10 00 00 7C F1 }

	condition:
		all of them
}
