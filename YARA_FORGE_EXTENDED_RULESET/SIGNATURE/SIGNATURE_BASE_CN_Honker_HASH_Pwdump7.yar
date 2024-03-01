rule SIGNATURE_BASE_CN_Honker_HASH_Pwdump7 : FILE
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file PwDump7.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "d61a1ac3-7c8a-5de2-a5a8-2a043b73f3b3"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/cn_pentestset_tools.yar#L577-L594"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "93a2d7c3a9b83371d96a575c15fe6fce6f9d50d3"
		logic_hash = "05f735ba3f377f71ccf3a97b3597cee7b9f36213ee2ebba19db69667529d9fac"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "%s\\SYSTEM32\\CONFIG\\SAM" fullword ascii
		$s2 = "No Users key!" fullword ascii
		$s3 = "NO PASSWORD*********************:" fullword ascii
		$s4 = "Unable to dump file %S" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <380KB and all of them
}
