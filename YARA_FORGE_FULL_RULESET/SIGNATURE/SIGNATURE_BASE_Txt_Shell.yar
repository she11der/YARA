rule SIGNATURE_BASE_Txt_Shell : FILE
{
	meta:
		description = "Chinese Hacktool Set - Webshells - file shell.c"
		author = "Florian Roth (Nextron Systems)"
		id = "3e4c5928-346e-541b-b1a8-b37d5e3abc98"
		date = "2015-06-14"
		modified = "2023-12-05"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_cn_webshells.yar#L479-L496"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "8342b634636ef8b3235db0600a63cc0ce1c06b62"
		logic_hash = "020e9e6ef776a9d69939fa3dec771dc516b0184086738bab439063acca89bd76"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "printf(\"Could not connect to remote shell!\\n\");" fullword ascii
		$s2 = "printf(\"Usage: %s <reflect ip> <port>\\n\", prog);" fullword ascii
		$s3 = "execl(shell,\"/bin/sh\",(char *)0);" fullword ascii
		$s4 = "char shell[]=\"/bin/sh\";" fullword ascii
		$s5 = "connect back door\\n\\n\");" fullword ascii

	condition:
		filesize <2KB and 2 of them
}
