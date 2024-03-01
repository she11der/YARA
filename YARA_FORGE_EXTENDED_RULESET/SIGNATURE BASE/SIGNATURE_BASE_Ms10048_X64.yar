rule SIGNATURE_BASE_Ms10048_X64 : FILE
{
	meta:
		description = "Chinese Hacktool Set - file ms10048-x64.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "8c9bcf72-1bc7-57ed-9e0b-09d113a8c704"
		date = "2015-06-13"
		modified = "2023-12-05"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_cn_hacktools.yar#L2362-L2378"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "418bec3493c85e3490e400ecaff5a7760c17a0d0"
		logic_hash = "f6e353a9e4f751632ca5fda1663f0ba66b16b60df90570ccdaf836eaaa6a78ca"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "The target is most likely patched." fullword ascii
		$s2 = "Dojibiron by Ronald Huizer, (c) master#h4cker.us  " fullword ascii
		$s3 = "[ ] Creating evil window" fullword ascii
		$s4 = "[+] Set to %d exploit half succeeded" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <40KB and 1 of them
}
