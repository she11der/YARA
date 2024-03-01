rule SIGNATURE_BASE_CN_Honker_Webshell_Picloaked_1 : FILE
{
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file 1.gif"
		author = "Florian Roth (Nextron Systems)"
		id = "2ff44c4a-ed97-5635-9926-8d54a8364fab"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/cn_pentestset_webshells.yar#L283-L299"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "3eab1798cbc9ab3b2c67d3da7b418d07e775db70"
		logic_hash = "a816ac9e98b7c5208f075ffcb9a6525016d6a5c468005d78ecab90d651423705"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "<?php eval($_POST[" ascii
		$s1 = ";<%execute(request(" ascii
		$s3 = "GIF89a" fullword ascii

	condition:
		filesize <6KB and 2 of them
}
