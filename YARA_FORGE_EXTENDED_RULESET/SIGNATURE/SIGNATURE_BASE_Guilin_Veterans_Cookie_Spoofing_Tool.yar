rule SIGNATURE_BASE_Guilin_Veterans_Cookie_Spoofing_Tool : FILE
{
	meta:
		description = "Chinese Hacktool Set - file Guilin veterans cookie spoofing tool.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "13f78e0b-c975-5879-9af1-8c619d6c94a9"
		date = "2015-06-13"
		modified = "2023-01-27"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_cn_hacktools.yar#L50-L67"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "06b1969bc35b2ee8d66f7ce8a2120d3016a00bb1"
		logic_hash = "5fd136f44ebce28db4f77f2f8730eb67fc4c2d58921b73378b8d87e1444a4b67"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "kernel32.dll^G" fullword ascii
		$s1 = "\\.Sus\"B" ascii
		$s4 = "u56Load3" fullword ascii
		$s11 = "O MYTMP(iM) VALUES (" ascii

	condition:
		uint16(0)==0x5a4d and filesize <1387KB and all of them
}
