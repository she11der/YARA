rule SIGNATURE_BASE_Idtools_For_Winxp_Idttool : FILE
{
	meta:
		description = "Chinese Hacktool Set - file IdtTool.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "c157d467-87f8-59d5-a3ba-e4fbeeba767d"
		date = "2015-06-13"
		modified = "2023-12-05"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_cn_hacktools.yar#L404-L419"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "ebab6e4cb7ea82c8dc1fe4154e040e241f4672c6"
		logic_hash = "9e14db3721afaba3ea5e9767afff593bf2b137306fe673acd7926bf6efc78391"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s2 = "IdtTool.sys" fullword ascii
		$s4 = "Idt Tool bY tMd[CsP]" fullword wide
		$s6 = "\\\\.\\slIdtTool" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <25KB and all of them
}
