rule SIGNATURE_BASE_Webshell_Zyklonshell
{
	meta:
		description = "PHP Webshells Github Archive - file ZyklonShell.php"
		author = "Florian Roth (Nextron Systems)"
		id = "4d7ff3e5-4940-52c8-b045-5db1523f70c2"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-webshells.yar#L6572-L6586"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "3fa7e6f3566427196ac47551392e2386a038d61c"
		logic_hash = "5d49f2599781836156f6bbb0c50cfcffdb2ca51c7cb688abbc6245d7f856ad01"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "The requested URL /Nemo/shell/zyklonshell.txt was not found on this server.<P>" fullword
		$s1 = "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">" fullword
		$s2 = "<TITLE>404 Not Found</TITLE>" fullword
		$s3 = "<H1>Not Found</H1>" fullword

	condition:
		all of them
}
