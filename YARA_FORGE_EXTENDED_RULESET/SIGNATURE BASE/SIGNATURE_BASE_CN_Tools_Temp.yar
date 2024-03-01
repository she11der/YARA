rule SIGNATURE_BASE_CN_Tools_Temp : FILE
{
	meta:
		description = "Chinese Hacktool Set - file Temp.war"
		author = "Florian Roth (Nextron Systems)"
		id = "4fbaabd0-fbf2-56a0-94af-9deba1e7cc81"
		date = "2015-06-13"
		modified = "2023-12-05"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_cn_hacktool_scripts.yar#L26-L42"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "c3327ef63b0ed64c4906e9940ef877c76ebaff58"
		logic_hash = "05fd1cb3f7c8b96ccf824013c130a0b21f43724463f8658e23239d009be7f4fe"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "META-INF/context.xml<?xml version=\"1.0\" encoding=\"UTF-8\"?>" fullword ascii
		$s1 = "browser.jsp" fullword ascii
		$s3 = "cmd.jsp" fullword ascii
		$s4 = "index.jsp" fullword ascii

	condition:
		uint16(0)==0x4b50 and filesize <203KB and all of them
}
