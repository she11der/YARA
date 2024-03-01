rule SIGNATURE_BASE_Cndcom_Cndcom : FILE
{
	meta:
		description = "Chinese Hacktool Set - file cndcom.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "b1acfe34-03b8-5909-a226-3325fe8629ab"
		date = "2015-06-13"
		modified = "2023-12-05"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_cn_hacktools.yar#L968-L988"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "08bbe6312342b28b43201125bd8c518531de8082"
		logic_hash = "226be7ea7b09b2b87eeec006c8054b9fb59eb8324def14a4a0db97f94fb39d62"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "- Rewritten by HDM last <hdm [at] metasploit.com>" fullword ascii
		$s2 = "- Usage: %s <Target ID> <Target IP>" fullword ascii
		$s3 = "- Remote DCOM RPC Buffer Overflow Exploit" fullword ascii
		$s4 = "- Warning:This Code is more like a dos tool!(Modify by pingker)" fullword ascii
		$s5 = "Windows NT SP6 (Chinese)" fullword ascii
		$s6 = "- Original code by FlashSky and Benjurry" fullword ascii
		$s7 = "\\C$\\123456111111111111111.doc" wide
		$s8 = "shell3all.c" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <100KB and 2 of them
}
