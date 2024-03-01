rule SIGNATURE_BASE_CN_Honker_Sig_3389_Dubrute_V3_0_RC3_2_0 : FILE
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file 2.0.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "dda5eea9-da79-5f1f-bbac-9f05ba7e71c9"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/cn_pentestset_tools.yar#L1683-L1699"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "e8ee982421ccff96121ffd24a3d84e3079f3750f"
		logic_hash = "8c9be7e8cc04eba6b131acc3c85ac48d7663260a2e4064ad55ed8f40e0875cf4"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "IP - %d; Login - %d; Password - %d; Combination - %d" fullword ascii
		$s3 = "Create %d IP@Loginl;Password" fullword ascii
		$s15 = "UBrute.com" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <980KB and 2 of them
}
