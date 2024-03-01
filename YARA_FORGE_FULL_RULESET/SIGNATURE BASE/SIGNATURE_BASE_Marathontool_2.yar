rule SIGNATURE_BASE_Marathontool_2 : FILE
{
	meta:
		description = "Chinese Hacktool Set - file MarathonTool.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "20151673-6779-58ce-872c-81e74a96597d"
		date = "2015-06-13"
		modified = "2023-12-05"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_cn_hacktools.yar#L510-L525"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "75b5d25cdaa6a035981e5a33198fef0117c27c9c"
		logic_hash = "7581b63a7bddeac93c65b2943b9f5f568464d8f300bc7385ca73880996bd390b"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s3 = "http://localhost/retomysql/pista.aspx?id_pista=1" fullword wide
		$s6 = "SELECT ASCII(SUBSTR(username,{0},1)) FROM USER_USERS" fullword wide
		$s17 = "/Blind SQL injection tool based in heavy queries" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <1000KB and all of them
}
