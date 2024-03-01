rule SIGNATURE_BASE_Stuxnet_Maindll_Decrypted_Unpacked
{
	meta:
		description = "Stuxnet Sample - file maindll.decrypted.unpacked.dll_"
		author = "Florian Roth (Nextron Systems)"
		id = "7009a41c-0588-5392-ae1c-045e0a5ee56b"
		date = "2016-07-09"
		modified = "2023-12-05"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_stuxnet.yar#L130-L150"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "bec740cdb4c1748d0fb546691cf8feb38c0e61adad60c069c5866f5034cb7ed9"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "4c3d7b38339d7b8adf73eaf85f0eb9fab4420585c6ab6950ebd360428af11712"

	strings:
		$s1 = "%SystemRoot%\\system32\\Drivers\\mrxsmb.sys;%SystemRoot%\\system32\\Drivers\\*.sys" fullword wide
		$s2 = "<Actions Context=\"%s\"><Exec><Command>%s</Command><Arguments>%s,#%u</Arguments></Exec></Actions>" fullword wide
		$s3 = "%SystemRoot%\\inf\\oem7A.PNF" fullword wide
		$s4 = "%SystemRoot%\\inf\\mdmcpq3.PNF" fullword wide
		$s5 = "%SystemRoot%\\inf\\oem6C.PNF" fullword wide
		$s6 = "@abf varbinary(4096) EXEC @hr = sp_OACreate 'ADODB.Stream', @aods OUT IF @hr <> 0 GOTO endq EXEC @hr = sp_OASetProperty @" wide
		$s7 = "STORAGE#Volume#1&19f7e59c&0&" fullword wide
		$s8 = "view MCPVREADVARPERCON as select VARIABLEID,VARIABLETYPEID,FORMATFITTING,SCALEID,VARIABLENAME,ADDRESSPARAMETER,PROTOKOLL,MAXLIMI" ascii

	condition:
		6 of them
}
