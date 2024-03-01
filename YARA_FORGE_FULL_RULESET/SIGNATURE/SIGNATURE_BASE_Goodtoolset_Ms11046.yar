rule SIGNATURE_BASE_Goodtoolset_Ms11046 : FILE
{
	meta:
		description = "Chinese Hacktool Set - file ms11046.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "a4703861-02a9-5d93-b6de-c3664ca8abb9"
		date = "2015-06-13"
		modified = "2023-12-05"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_cn_hacktools.yar#L421-L438"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "f8414a374011fd239a6c6d9c6ca5851cd8936409"
		logic_hash = "2fb36a589613f97d0c3a4da58c65352689062a8ba6d432b5f3cf3b51a7e77f8c"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "[*] Token system command" fullword ascii
		$s2 = "[*] command add user 90sec 90sec" fullword ascii
		$s3 = "[*] Add to Administrators success" fullword ascii
		$s4 = "[*] User has been successfully added" fullword ascii
		$s5 = "Program: %s%s%s%s%s%s%s%s%s%s%s" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <840KB and 2 of them
}
