rule SIGNATURE_BASE_Webshell_Networkfilemanagerphp
{
	meta:
		description = "Web Shell - file NetworkFileManagerPHP.php"
		author = "Florian Roth (Nextron Systems)"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
		date = "2014-01-28"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-webshells.yar#L420-L433"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "acdbba993a5a4186fd864c5e4ea0ba4f"
		logic_hash = "235e4062a9b9ebdf7dd0b8a2cb3b16ba7688a75b90d8c527344cf9605304838d"
		score = 70
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s9 = "  echo \"<br><center>All the data in these tables:<br> \".$tblsv.\" were putted "

	condition:
		all of them
}
