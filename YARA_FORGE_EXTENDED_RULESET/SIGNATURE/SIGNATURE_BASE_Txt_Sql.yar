rule SIGNATURE_BASE_Txt_Sql : FILE
{
	meta:
		description = "Chinese Hacktool Set - Webshells - file Sql.txt"
		author = "Florian Roth (Nextron Systems)"
		id = "586f23d4-3a04-520d-b75b-f9bbcf67ceeb"
		date = "2015-06-14"
		modified = "2023-12-05"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_cn_webshells.yar#L683-L699"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "f7813f1dfa4eec9a90886c80b88aa38e2adc25d5"
		logic_hash = "0712b6736d8bdc1f19b3494dc3aab9e9a04dde167b5f843e319755cd311e29bd"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "cmd=chr(34)&\"cmd.exe /c \"&request.form(\"cmd\")&\" > 8617.tmp\"&chr(34)" fullword ascii
		$s2 = "strQuery=\"dbcc addextendedproc ('xp_regwrite','xpstar.dll')\"" fullword ascii
		$s3 = "strQuery = \"exec master.dbo.xp_cmdshell '\" & request.form(\"cmd\") & \"'\" " fullword ascii
		$s4 = "session(\"login\")=\"\"" fullword ascii

	condition:
		filesize <15KB and all of them
}
