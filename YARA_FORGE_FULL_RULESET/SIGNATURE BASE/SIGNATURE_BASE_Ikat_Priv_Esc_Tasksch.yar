import "pe"

rule SIGNATURE_BASE_Ikat_Priv_Esc_Tasksch
{
	meta:
		description = "Task Schedulder Local Exploit - Windows local priv-esc using Task Scheduler, published by webDevil. Supports Windows 7 and Vista."
		author = "Florian Roth (Nextron Systems)"
		id = "0786b313-3154-536b-b7eb-c4d8444a309f"
		date = "2014-05-11"
		modified = "2023-12-05"
		reference = "http://ikat.ha.cked.net/Windows/functions/ikatfiles.html"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-hacktools.yar#L815-L841"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "84ab94bff7abf10ffe4446ff280f071f9702cf8b"
		logic_hash = "6d0f755a758aaac4328f5f4343b424c03c2751ddad6a1dbe7c0332171c027945"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "objShell.Run \"schtasks /change /TN wDw00t /disable\",,True" fullword ascii
		$s3 = "objShell.Run \"schtasks /run /TN wDw00t\",,True" fullword ascii
		$s4 = "'objShell.Run \"cmd /c copy C:\\windows\\system32\\tasks\\wDw00t .\",,True" fullword ascii
		$s6 = "a.WriteLine (\"schtasks /delete /f /TN wDw00t\")" fullword ascii
		$s7 = "a.WriteLine (\"net user /add ikat ikat\")" fullword ascii
		$s8 = "a.WriteLine (\"cmd.exe\")" fullword ascii
		$s9 = "strFileName=\"C:\\windows\\system32\\tasks\\wDw00t\"" fullword ascii
		$s10 = "For n = 1 To (Len (hexXML) - 1) step 2" fullword ascii
		$s13 = "output.writeline \" Should work on Vista/Win7/2008 x86/x64\"" fullword ascii
		$s11 = "Set objExecObject = objShell.Exec(\"cmd /c schtasks /query /XML /TN wDw00t\")" fullword ascii
		$s12 = "objShell.Run \"schtasks /create /TN wDw00t /sc monthly /tr \"\"\"+biatchFile+\"" ascii
		$s14 = "a.WriteLine (\"net localgroup administrators /add v4l\")" fullword ascii
		$s20 = "Set ts = fso.createtextfile (\"wDw00t.xml\")" fullword ascii

	condition:
		2 of them
}
