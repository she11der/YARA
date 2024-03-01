rule SIGNATURE_BASE_Dbgiis6Cli
{
	meta:
		description = "Webshells Auto-generated - file dbgiis6cli.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "2bc59a6b-f45c-5e68-a346-ac56e8f2757b"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-webshells.yar#L8300-L8312"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "3044dceb632b636563f66fee3aaaf8f3"
		logic_hash = "f6de3c9b8fbcca230540d1b41659ab02c9548df69f53fa9d5730ac7bb7dfe88a"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "User-Agent: Mozilla/4.0 (compatible; MSIE 5.01; Windows NT 5.0)"
		$s5 = "###command:(NO more than 100 bytes!)"

	condition:
		all of them
}
