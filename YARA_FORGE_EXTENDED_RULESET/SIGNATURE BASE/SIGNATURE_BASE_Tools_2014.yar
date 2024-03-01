rule SIGNATURE_BASE_Tools_2014 : FILE
{
	meta:
		description = "Chinese Hacktool Set - file 2014.jsp"
		author = "Florian Roth (Nextron Systems)"
		id = "bb76321b-003d-5f6b-a84b-425477abe91c"
		date = "2015-06-13"
		modified = "2023-12-05"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_cn_webshells.yar#L174-L189"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "74518faf08637c53095697071db09d34dbe8d676"
		logic_hash = "caa365cc1a641b7dcd5d2082240d981e66caf6da1379ee109a0bb1f651d1f00f"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "((Invoker) ins.get(\"login\")).invoke(request, response," fullword ascii
		$s4 = "program = \"cmd.exe /c net start > \" + SHELL_DIR" fullword ascii
		$s5 = ": \"c:\\\\windows\\\\system32\\\\cmd.exe\")" fullword ascii

	condition:
		filesize <715KB and all of them
}
