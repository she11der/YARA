rule SIGNATURE_BASE_CN_Honker_Webshell_Serv_U_Servu : FILE
{
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file servu.php"
		author = "Florian Roth (Nextron Systems)"
		id = "3e50d991-7297-5766-b68a-e74aa34ce042"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/cn_pentestset_webshells.yar#L671-L686"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "7de701b86820096e486e64ca34f1fa9f2fbba641"
		logic_hash = "d3956b6daa0649233372aea4176e0d43c44d866146884222f92b7efe01f288bb"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "fputs ($conn_id, \"SITE EXEC \".$dir.\"cmd.exe /c \".$cmd.\"\\r\\n\");" fullword ascii
		$s1 = "function ftpcmd($ftpport,$user,$password,$dir,$cmd){" fullword ascii

	condition:
		filesize <41KB and all of them
}
