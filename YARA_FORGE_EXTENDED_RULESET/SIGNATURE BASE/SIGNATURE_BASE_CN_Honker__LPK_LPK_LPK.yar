rule SIGNATURE_BASE_CN_Honker__LPK_LPK_LPK : FILE
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - from files LPK.DAT, LPK.DAT, LPK.DAT"
		author = "Florian Roth (Nextron Systems)"
		id = "e1beb88b-d3e8-5868-affb-e59c26e4dc2e"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/cn_pentestset_tools.yar#L2400-L2421"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "0309241ed0e899519cf3edd1544a14d09fff4a8162514ae49b3a6b70eda1ed4f"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		super_rule = 1
		hash0 = "5a1226e73daba516c889328f295e728f07fdf1c3"
		hash1 = "2b2ab50753006f62965bba83460e3960ca7e1926"
		hash2 = "cf2549bbbbdb7aaf232d9783873667e35c8d96c1"

	strings:
		$s1 = "C:\\WINDOWS\\system32\\cmd.exe" fullword wide
		$s2 = "Password error!" fullword ascii
		$s3 = "\\sathc.exe" ascii
		$s4 = "\\sothc.exe" ascii
		$s5 = "\\lpksethc.bat" ascii

	condition:
		uint16(0)==0x5a4d and filesize <1057KB and all of them
}
