rule SIGNATURE_BASE_CN_Honker_Webshell_ASP_Asp2 : FILE
{
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file asp2.txt"
		author = "Florian Roth (Nextron Systems)"
		id = "e5296405-c345-55dc-acd9-be6aca86c60b"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/cn_pentestset_webshells.yar#L993-L1009"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "b3ac478e72a0457798a3532f6799adeaf4a7fc87"
		logic_hash = "6107afe9895c4e0c865e78bece160246815a0d3c589bfc79f8b369b94481cd89"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "<%=server.mappath(request.servervariables(\"script_name\"))%>" fullword ascii
		$s2 = "webshell</font> <font color=#00FF00>" fullword ascii
		$s3 = "Userpwd = \"admin\"   'User Password" fullword ascii

	condition:
		filesize <10KB and all of them
}
