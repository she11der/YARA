rule SIGNATURE_BASE_Dbexpora : FILE
{
	meta:
		description = "Chinese Hacktool Set - file dbexpora.dll"
		author = "Florian Roth (Nextron Systems)"
		id = "43297ce9-60f3-5b69-b7d8-904fffe622fe"
		date = "2015-06-13"
		modified = "2023-12-05"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_cn_hacktools.yar#L656-L671"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "b55b007ef091b2f33f7042814614564625a8c79f"
		logic_hash = "2dad6cedae6a3a446c2c4829516bffa5608ea4d1c13c907796cf4d13ec37965e"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "SELECT A.USER FROM SYS.USER_USERS A " fullword ascii
		$s12 = "OCI 8 - OCIDescriptorFree" fullword ascii
		$s13 = "ORACommand *" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <835KB and all of them
}
