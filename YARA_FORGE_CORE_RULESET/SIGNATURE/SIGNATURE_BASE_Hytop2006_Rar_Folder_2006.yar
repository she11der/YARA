rule SIGNATURE_BASE_Hytop2006_Rar_Folder_2006
{
	meta:
		description = "Webshells Auto-generated - file 2006.asp"
		author = "Florian Roth (Nextron Systems)"
		id = "bda89055-27f5-50b7-86a3-2c75a5f3eadc"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/thor-webshells.yar#L8973-L8984"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		hash = "c19d6f4e069188f19b08fa94d44bc283"
		logic_hash = "536232bbdd21bddb88eefe06a82927abcdd3ed10404c052957896960a6d10932"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s6 = "strBackDoor = strBackDoor "

	condition:
		all of them
}
