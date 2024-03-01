rule SIGNATURE_BASE_Sqltools : FILE
{
	meta:
		description = "Chinese Hacktool Set - file SQLTools.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "bddb7956-abc1-58b6-8a6d-eb482be99f42"
		date = "2015-06-13"
		modified = "2023-12-05"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_cn_hacktools.yar#L2167-L2186"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "38a9caa2079afa2c8d7327e7762f7ed9a69056f7"
		logic_hash = "35b84c3445e92d61ca5e638a2eb19128dca2174327c6325436287d8d3f0bb976"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "DBN_POST" fullword wide
		$s2 = "LOADER ERROR" fullword ascii
		$s3 = "www.1285.net" fullword wide
		$s4 = "TUPFILEFORM" fullword wide
		$s5 = "DBN_DELETE" fullword wide
		$s6 = "DBINSERT" fullword wide
		$s7 = "Copyright (C) Kibosoft Corp. 2001-2006" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <2350KB and all of them
}
