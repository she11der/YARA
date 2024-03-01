rule COD3NYM_SUSP_OBF_NET_Confuserex_Name_Pattern_Jan24 : FILE
{
	meta:
		description = "Detects Naming Pattern used by ConfuserEx. ConfuserEx is a widely used open source obfuscator often found in malware"
		author = "Jonathan Peters"
		id = "2b57f135-9d9d-5401-be29-a1053f4249ec"
		date = "2024-01-03"
		modified = "2024-01-09"
		reference = "https://github.com/yck1509/ConfuserEx/tree/master"
		source_url = "https://github.com/cod3nym/detection-rules//blob/ad485bff0ce30afb56e367b7f2b76fea81e78fc9/yara/dotnet/obf_confuserex.yar#L1-L21"
		license_url = "https://github.com/cod3nym/detection-rules//blob/ad485bff0ce30afb56e367b7f2b76fea81e78fc9/LICENSE.md"
		hash = "2f67f590cabb9c79257d27b578d8bf9d1a278afa96b205ad2b4704e7b9a87ca7"
		logic_hash = "f28f3bd61c6f257cc622f6f323a5b5113d7d7b79ce8b852df02c42af22ecf033"
		score = 50
		quality = 80
		tags = "FILE"

	strings:
		$s1 = "mscoree.dll" ascii
		$s2 = "mscorlib" ascii
		$s3 = "System.Private.Corlib" ascii
		$s4 = "#Strings" ascii
		$s5 = { 5F 43 6F 72 [3] 4D 61 69 6E }
		$name_pattern = { E2 ( 80 8? | 81 AA ) E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 80 AE}

	condition:
		uint16(0)==0x5a4d and 2 of ($s*) and #name_pattern>5
}
