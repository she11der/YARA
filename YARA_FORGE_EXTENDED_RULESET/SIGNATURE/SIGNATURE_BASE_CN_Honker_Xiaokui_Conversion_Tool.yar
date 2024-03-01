rule SIGNATURE_BASE_CN_Honker_Xiaokui_Conversion_Tool : FILE
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file Xiaokui_conversion_tool.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "26e30df6-b1d9-5d82-b368-a4a904939aa3"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/cn_pentestset_tools.yar#L1082-L1098"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "dccd163e94a774b01f90c1e79f186894e2f27de3"
		logic_hash = "66a77c1fbfecdc02f591c12f69b46e39b7077dfbb5ed2a26a7dcfb11c8b464dc"
		score = 70
		quality = 60
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "update [dv_user] set usergroupid=1 where userid=2;--" fullword ascii
		$s2 = "To.exe" fullword wide
		$s3 = "by zj1244" ascii

	condition:
		uint16(0)==0x5a4d and filesize <240KB and 2 of them
}
