rule SIGNATURE_BASE_CN_Honker_Webshell_Tuoku_Script_Oracle : FILE
{
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file oracle.jsp"
		author = "Florian Roth (Nextron Systems)"
		id = "adc8dea6-8031-580b-b19a-e5520d41528f"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/cn_pentestset_webshells.yar#L493-L509"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "fc7043aaac0ee2d860d11f18ddfffbede9d07957"
		logic_hash = "3ad4207e426ed2f9df0e0bac0e906af437b0774ba2ebb541afbe7e29b395ad63"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "String url=\"jdbc:oracle:thin:@localhost:1521:orcl\";" fullword ascii
		$s2 = "String user=\"oracle_admin\";" fullword ascii
		$s3 = "String sql=\"SELECT 1,2,3,4,5,6,7,8,9,10 from user_info\";" fullword ascii

	condition:
		filesize <7KB and all of them
}
