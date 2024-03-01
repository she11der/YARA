rule SIGNATURE_BASE_CN_Honker_Webshell_PHP_Php8 : FILE
{
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file php8.txt"
		author = "Florian Roth (Nextron Systems)"
		id = "8b25b7f3-b94e-5887-b102-b52d340a4316"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/cn_pentestset_webshells.yar#L317-L334"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "b7b49f1d6645865691eccd025e140c521ff01cce"
		logic_hash = "435ceb72c082f702284c464979a907a59a42bb4aa07311f9b2da1a9831efac11"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "<a href=\"http://hi.baidu.com/ca3tie1/home\" target=\"_blank\">Ca3tie1's Blog</a" ascii
		$s1 = "function startfile($path = 'dodo.zip')" fullword ascii
		$s3 = "<form name=\"myform\" method=\"post\" action=\"\">" fullword ascii
		$s5 = "$_REQUEST[zipname] = \"dodozip.zip\"; " fullword ascii

	condition:
		filesize <25KB and 2 of them
}
