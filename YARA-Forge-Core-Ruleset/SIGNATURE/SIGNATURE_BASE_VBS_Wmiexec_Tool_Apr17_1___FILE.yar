rule SIGNATURE_BASE_VBS_Wmiexec_Tool_Apr17_1___FILE
{
	meta:
		description = "Tools related to Operation Cloud Hopper"
		author = "Florian Roth (Nextron Systems)"
		id = "8175eb74-38f1-5d8f-a668-aa8e215b032e"
		date = "2017-04-07"
		modified = "2023-12-05"
		reference = "https://github.com/maaaaz/impacket-examples-windows"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_op_cloudhopper.yar#L295-L318"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "b0aad1c8dfc07ae3df835ae113bd02abfd706a0646ffcac5dd5691822016d31a"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "21bc328ed8ae81151e7537c27c0d6df6d47ba8909aebd61333e32155d01f3b11"

	strings:
		$x1 = "strNetUse = \"cmd.exe /c net use \\\\\" & host" fullword ascii
		$x2 = "localcmd = \"cmd.exe /c \" & command " ascii
		$x3 = "& \" > \" & TempFile & \" 2>&1\"  '2>&1 err" fullword ascii
		$x4 = "strExec = \"cmd.exe /c \" & cmd & \" >> \" & resultfile & \" 2>&1\"  '2>&1 err" fullword ascii
		$x5 = "TempFile = objShell.ExpandEnvironmentStrings(\"%TEMP%\") & \"\\wmi.dll\"" fullword ascii
		$a1 = "WMIEXEC ERROR: Command -> " ascii
		$a2 = "WMIEXEC : Command result will output to" fullword ascii
		$a3 = "WMIEXEC : Target ->" fullword ascii
		$a4 = "WMIEXEC : Login -> OK" fullword ascii
		$a5 = "WMIEXEC : Process created. PID:" fullword ascii

	condition:
		( filesize <40KB and 1 of them ) or 3 of them
}