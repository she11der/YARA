rule SIGNATURE_BASE_CN_Honker_Webshell_Wshell_Asp : FILE
{
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file wshell-asp.txt"
		author = "Florian Roth (Nextron Systems)"
		id = "294f0d00-7102-553d-92e2-c0a0e017385c"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/cn_pentestset_webshells.yar#L405-L421"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "4a0afdf5a45a759c14e99eb5315964368ca53e9c"
		logic_hash = "f3c4af85e4798d3a809d8edd9cc46d1df44453f14ed050b002fe789da4d6096f"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "file1.Write(\"<%response.clear:execute request(\\\"root\\\"):response.End%>\");" fullword ascii
		$s2 = "hello word !  " fullword ascii
		$s3 = "root.asp " fullword ascii

	condition:
		filesize <5KB and all of them
}
