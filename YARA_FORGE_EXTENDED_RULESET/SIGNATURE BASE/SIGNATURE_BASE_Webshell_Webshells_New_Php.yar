rule SIGNATURE_BASE_Webshell_Webshells_New_PHP
{
	meta:
		description = "Web shells - generated from file PHP.php"
		author = "Florian Roth (Nextron Systems)"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
		date = "2014-03-28"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-webshells.yar#L3582-L3599"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "a524e7ae8d71e37d2fd3e5fbdab405ea"
		logic_hash = "706f835f63e153f907ae8a5a48f1dc4b9d3b8511b21b7155bc045b0ebdc893fc"
		score = 70
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "echo \"<font color=blue>Error!</font>\";" fullword
		$s2 = "<input type=\"text\" size=61 name=\"f\" value='<?php echo $_SERVER[\"SCRIPT_FILE"
		$s5 = " - ExpDoor.com</title>" fullword
		$s10 = "$f=fopen($_POST[\"f\"],\"w\");" fullword
		$s12 = "<textarea name=\"c\" cols=60 rows=15></textarea><br>" fullword

	condition:
		1 of them
}
