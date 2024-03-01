rule SIGNATURE_BASE_Ironpanda_Webshell_JSP : FILE
{
	meta:
		description = "Iron Panda Malware JSP"
		author = "Florian Roth (Nextron Systems)"
		id = "38125418-7867-5073-a731-4f1d64e07588"
		date = "2015-09-16"
		modified = "2023-12-05"
		reference = "https://goo.gl/E4qia9"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_irontiger.yar#L57-L72"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "3be95477e1d9f3877b4355cff3fbcdd3589bb7f6349fd4ba6451e1e9d32b7fa6"
		logic_hash = "747ce812b156bf03f8d14ef84e7d2e8535c7c70590dfcb50ce3e957bec745efc"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "Bin_ExecSql(\"exec master..xp_cmdshell'bcp \\\"select safile from \" + db + \"..bin_temp\\\" queryout \\\"\" + Bin_TextBox_SaveP" ascii
		$s2 = "tc.Text=\"<a href=\\\"javascript:Bin_PostBack('zcg_ClosePM','\"+Bin_ToBase64(de.Key.ToString())+\"')\\\">Close</a>\";" fullword ascii
		$s3 = "Bin_ExecSql(\"IF OBJECT_ID('bin_temp')IS NOT NULL DROP TABLE bin_temp\");" fullword ascii

	condition:
		filesize <330KB and 1 of them
}
