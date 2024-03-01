rule SIGNATURE_BASE_Webshell_Wsb_Idc
{
	meta:
		description = "Web Shell - file idc.php"
		author = "Florian Roth (Nextron Systems)"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
		date = "2014-01-28"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-webshells.yar#L1012-L1026"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "7c5b1b30196c51f1accbffb80296395f"
		logic_hash = "f274061f1a02ab65bc574a6586343f74262a463c5200cd2c231a752f54967404"
		score = 70
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "if (md5($_GET['usr'])==$user && md5($_GET['pass'])==$pass)" fullword
		$s3 = "{eval($_GET['idc']);}" fullword

	condition:
		1 of them
}
