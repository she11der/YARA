rule SIGNATURE_BASE_Mswin_Check_Lm_Group : FILE
{
	meta:
		description = "Chinese Hacktool Set - file mswin_check_lm_group.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "be17981a-7cbf-55ac-bc81-9330472fc814"
		date = "2015-06-13"
		modified = "2021-03-15"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_cn_hacktools.yar#L9-L28"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "115d87d7e7a3d08802a9e5fd6cd08e2ec633c367"
		logic_hash = "74be6bd9c6e01cc4ec7785b6950c8cf6acf549c06990a9d1734f4a3487a04ba7"
		score = 70
		quality = 85
		tags = "FILE"

	strings:
		$s1 = "Valid_Global_Groups: checking group membership of '%s\\%s'." fullword ascii
		$s2 = "Usage: %s [-D domain][-G][-P][-c][-d][-h]" fullword ascii
		$s3 = "-D    default user Domain" fullword ascii
		$fp1 = "Panda Security S.L." ascii wide

	condition:
		uint16(0)==0x5a4d and filesize <380KB and all of ($s*) and not 1 of ($fp*)
}
