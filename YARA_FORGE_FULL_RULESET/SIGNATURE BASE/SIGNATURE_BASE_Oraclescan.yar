rule SIGNATURE_BASE_Oraclescan : FILE
{
	meta:
		description = "Chinese Hacktool Set - file OracleScan.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "142c0ed1-0752-54c3-9a4b-68e656c32939"
		date = "2015-06-13"
		modified = "2023-12-05"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_cn_hacktools.yar#L2149-L2165"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "10ff7faf72fe6da8f05526367b3522a2408999ec"
		logic_hash = "b9454f47123c32d6c6b51722aeadac9acc2a6232c259703c36ea00c83d8977e6"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "MYBLOG:HTTP://HI.BAIDU.COM/0X24Q" fullword ascii
		$s2 = "\\Borland\\Delphi\\RTL" ascii
		$s3 = "USER_NAME" ascii
		$s4 = "FROMWWHERE" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <300KB and all of them
}
