rule SIGNATURE_BASE_CN_Honker_Webshell_Jspshell2 : FILE
{
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file jspshell2.txt"
		author = "Florian Roth (Nextron Systems)"
		id = "ff72f94b-1c0a-5615-b35f-35f69c920292"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/cn_pentestset_webshells.yar#L760-L775"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "cc7bc1460416663012fc93d52e2078c0a277ff79"
		logic_hash = "3a60991fa557655fbd2450739976ac612a0ea2a3df22873382b05438cac12762"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s10 = "if (cmd == null) cmd = \"cmd.exe /c set\";" fullword ascii
		$s11 = "if (program == null) program = \"cmd.exe /c net start > \"+SHELL_DIR+\"/Log.txt" ascii

	condition:
		filesize <424KB and all of them
}
