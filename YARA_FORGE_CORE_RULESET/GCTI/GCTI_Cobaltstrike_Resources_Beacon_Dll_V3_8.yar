rule GCTI_Cobaltstrike_Resources_Beacon_Dll_V3_8
{
	meta:
		description = "Cobalt Strike's resources/beacon.dll Versions 3.8"
		author = "gssincla@google.com"
		id = "f76712a4-df1c-5e6b-b5ac-9c74f2e202fc"
		date = "2022-11-18"
		modified = "2023-12-04"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		source_url = "https://github.com/chronicle/GCTI/blob/1c5fd42b1895098527fde00c2d9757edf6b303bb/YARA/CobaltStrike/CobaltStrike__Resources_Beacon_Dll_All_Versions_MemEnabled.yara#L691-L731"
		license_url = "https://github.com/chronicle/GCTI/blob/1c5fd42b1895098527fde00c2d9757edf6b303bb/LICENSE"
		hash = "67b6557f614af118a4c409c992c0d9a0cc800025f77861ecf1f3bbc7c293d603"
		logic_hash = "a0c78dd7cda055bc76a8661b0416a302d7b05d03eeea483d2d1695093cd6dc90"
		score = 75
		quality = 85
		tags = ""

	strings:
		$version_sig = { 48 57 8B F9 83 F8 4B 0F 87 5D 03 00 00 FF 24 }
		$decoder = { 80 B0 [4] ?? 40 3D 00 10 00 00 7C F1 }
		$xmrig_srcpath = "C:/Users/SKOL-NOTE/Desktop/Loader/script.go"
		$c2_1 = "ns7.softline.top" xor
		$c2_2 = "ns8.softline.top" xor
		$c2_3 = "ns9.softline.top" xor

	condition:
		$version_sig and $decoder and not (2 of ($c2_*) or $xmrig_srcpath)
}
