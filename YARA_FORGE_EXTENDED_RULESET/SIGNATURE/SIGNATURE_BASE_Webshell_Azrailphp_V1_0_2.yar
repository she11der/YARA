rule SIGNATURE_BASE_Webshell_Azrailphp_V1_0_2
{
	meta:
		description = "PHP Webshells Github Archive - file aZRaiLPhp v1.0.php"
		author = "Florian Roth (Nextron Systems)"
		id = "10546549-e16d-567d-9d88-3d37fe8ff03f"
		date = "2023-12-05"
		modified = "2023-12-05"
		old_rule_name = "WebShell_aZRaiLPhp_v1_0"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-webshells.yar#L6648-L6663"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "a2c609d1a8c8ba3d706d1d70bef69e63f239782b"
		logic_hash = "8309338bb327cc14ae5970bd921b3dba68353d55be31b9dbbc5374ded24ed563"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "<font size='+1'color='#0000FF'>aZRaiLPhP'nin URL'si: http://$HTTP_HOST$RED"
		$s4 = "$fileperm=base_convert($_POST['fileperm'],8,10);" fullword
		$s19 = "touch (\"$path/$dismi\") or die(\"Dosya Olu" fullword
		$s20 = "echo \"<div align=left><a href='./$this_file?dir=$path/$file'>G" fullword

	condition:
		2 of them
}
