rule SIGNATURE_BASE_Chinachopper_Caidao : FILE
{
	meta:
		description = "Chinese Hacktool Set - file caidao.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "c56eb3e5-e916-535b-bf87-88a9ae94c359"
		date = "2015-06-13"
		modified = "2023-12-05"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_cn_hacktools.yar#L2241-L2259"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "056a60ec1f6a8959bfc43254d97527b003ae5edb"
		logic_hash = "7e16a452c98e36a4946bcede5552bef7f6fc82314b28b506307cf010a0890ea6"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "Pass,Config,n{)" fullword ascii
		$s2 = "phMYSQLZ" fullword ascii
		$s3 = "\\DHLP\\." ascii
		$s4 = "\\dhlp\\." ascii
		$s5 = "SHAutoComple" fullword ascii
		$s6 = "MainFrame" ascii

	condition:
		uint16(0)==0x5a4d and filesize <1077KB and all of them
}
