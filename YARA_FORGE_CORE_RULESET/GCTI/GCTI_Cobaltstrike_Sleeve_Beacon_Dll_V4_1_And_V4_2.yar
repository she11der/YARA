rule GCTI_Cobaltstrike_Sleeve_Beacon_Dll_V4_1_And_V4_2
{
	meta:
		description = "Cobalt Strike's sleeve/beacon.dll Versions 4.1 and 4.2"
		author = "gssincla@google.com"
		id = "793df916-bdf7-5743-b008-0113caf38bae"
		date = "2022-11-18"
		modified = "2023-12-04"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		source_url = "https://github.com/chronicle/GCTI/blob/1c5fd42b1895098527fde00c2d9757edf6b303bb/YARA/CobaltStrike/CobaltStrike__Resources_Beacon_Dll_All_Versions_MemEnabled.yara#L903-L934"
		license_url = "https://github.com/chronicle/GCTI/blob/1c5fd42b1895098527fde00c2d9757edf6b303bb/LICENSE"
		hash = "daa42f4380cccf8729129768f3588bb98e4833b0c40ad0620bb575b5674d5fc3"
		logic_hash = "7280a5c3f478ea40b6b72fb4669d5b8c21603e7fbfbc3815a83bc462ee19c0f5"
		score = 75
		quality = 85
		tags = ""
		rs2 = "9de55f27224a4ddb6b2643224a5da9478999c7b2dea3a3d6b3e1808148012bcf"

	strings:
		$version_sig = { 48 57 8B F2 83 F8 63 0F 87 3C 03 00 00 FF 24 }
		$decoder = { 80 B0 [4] ?? 40 3D 00 10 00 00 7C F1 }

	condition:
		all of them
}
