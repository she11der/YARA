rule SIGNATURE_BASE_CN_Tools_Pc : FILE
{
	meta:
		description = "Chinese Hacktool Set - file pc.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "11cc6c46-33c0-5c53-88f8-700be9ca8add"
		date = "2015-06-13"
		modified = "2023-12-05"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_cn_hacktools.yar#L1179-L1195"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "5cf8caba170ec461c44394f4058669d225a94285"
		logic_hash = "1da263362e4c2ec8194bb80bfc3f25ff8c4b708919ba02ea02687d5404b99720"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "\\svchost.exe" ascii
		$s2 = "%s%08x.001" fullword ascii
		$s3 = "Qy001Service" fullword ascii
		$s4 = "/.MIKY" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <300KB and all of them
}
