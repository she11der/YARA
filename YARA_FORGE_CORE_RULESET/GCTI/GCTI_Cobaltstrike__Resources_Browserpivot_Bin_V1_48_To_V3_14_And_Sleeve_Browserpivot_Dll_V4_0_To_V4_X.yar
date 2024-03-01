rule GCTI_Cobaltstrike__Resources_Browserpivot_Bin_V1_48_To_V3_14_And_Sleeve_Browserpivot_Dll_V4_0_To_V4_X
{
	meta:
		description = "Cobalt Strike's resources/browserpivot.bin from v1.48 to v3.14 and sleeve/browserpivot.dll from v4.0 to at least v4.4"
		author = "gssincla@google.com"
		id = "55086544-6684-526b-914f-505a562be458"
		date = "2022-11-18"
		modified = "2022-11-19"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		source_url = "https://github.com/chronicle/GCTI/blob/1c5fd42b1895098527fde00c2d9757edf6b303bb/YARA/CobaltStrike/CobaltStrike__Resources_Browserpivot_Bin_v1_48_to_v3_14_and_Sleeve_Browserpivot_Dll_v4_0_to_v4_x.yara#L17-L60"
		license_url = "https://github.com/chronicle/GCTI/blob/1c5fd42b1895098527fde00c2d9757edf6b303bb/LICENSE"
		hash = "12af9f5a7e9bfc49c82a33d38437e2f3f601639afbcdc9be264d3a8d84fd5539"
		logic_hash = "416554d31c105fd96aeaef508847efe2889590909c8d0025e3862e5b24078131"
		score = 75
		quality = 85
		tags = ""

	strings:
		$socket_recv = {
			FF [1-5]
			83 ?? FF 
			74 ?? 
			85 C0
			(74 | 76) ?? 
			03 ?? 
			83 ?? 02 
			72 ?? 
			80 ?? 3E FF 0A 
			75 ?? 
			80 ?? 3E FE 0D 
		}
		$fmt = "%1024[^ ] %8[^:]://%1016[^/]%7168[^ ] %1024[^ ]"

	condition:
		all of them
}
