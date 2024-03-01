rule SIGNATURE_BASE_CN_Honker_Webshell_Tuoku_Script_Xx : FILE
{
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file xx.php"
		author = "Florian Roth (Nextron Systems)"
		id = "72a04950-b82d-516f-a376-5253b7de1158"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/cn_pentestset_webshells.yar#L336-L352"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "2f39f1d9846ae72fc673f9166536dc21d8f396aa"
		logic_hash = "67c542f172fd1b97fbee4697fd42bab9486e3d779ce62993617e5a5205bd75d4"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "$mysql.=\"insert into `$table`($keys) values($vals);\\r\\n\";" fullword ascii
		$s2 = "$mysql_link=@mysql_connect($mysql_servername , $mysql_username , $mysql_password" ascii
		$s16 = "mysql_query(\"SET NAMES gbk\");" fullword ascii

	condition:
		filesize <2KB and all of them
}
