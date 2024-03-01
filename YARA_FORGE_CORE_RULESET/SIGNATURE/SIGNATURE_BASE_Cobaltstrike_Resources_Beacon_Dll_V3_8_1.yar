rule SIGNATURE_BASE_Cobaltstrike_Resources_Beacon_Dll_V3_8_1
{
	meta:
		description = "Cobalt Strike's resources/beacon.dll Versions 3.8"
		author = "gssincla@google.com"
		id = "6c65cbf8-2c60-5315-b3b2-48dfcee75733"
		date = "2022-11-18"
		modified = "2023-12-05"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/gen_gcti_cobaltstrike.yar#L1020-L1061"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		hash = "67b6557f614af118a4c409c992c0d9a0cc800025f77861ecf1f3bbc7c293d603"
		logic_hash = "cde078a6ae7d0d835900e85498cf5ae20663ba8d5d3f912810e157261561e16a"
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
		$version_sig and $decoder and (2 of ($c2_*) or $xmrig_srcpath)
}
