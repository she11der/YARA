rule SIGNATURE_BASE_Webshell_Ftpsearch
{
	meta:
		description = "PHP Webshells Github Archive - file ftpsearch.php"
		author = "Florian Roth (Nextron Systems)"
		id = "9db8f00a-1843-5057-b8c7-a7f7b63e0659"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-webshells.yar#L6722-L6736"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "c945f597552ccb8c0309ad6d2831c8cabdf4e2d6"
		logic_hash = "6b32553be4fdf26776e3cbb8a5d4d011d88f2bd50949b65934df72b89065aeec"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "echo \"[-] Error : coudn't read /etc/passwd\";" fullword
		$s9 = "@$ftp=ftp_connect('127.0.0.1');" fullword
		$s12 = "echo \"<title>Edited By KingDefacer</title><body>\";" fullword
		$s19 = "echo \"[+] Founded \".sizeof($users).\" entrys in /etc/passwd\\n\";" fullword

	condition:
		2 of them
}
