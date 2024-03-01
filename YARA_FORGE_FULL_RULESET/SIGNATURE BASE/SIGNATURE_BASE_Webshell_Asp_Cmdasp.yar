rule SIGNATURE_BASE_Webshell_Asp_Cmdasp
{
	meta:
		description = "Web Shell - file cmdasp.asp"
		author = "Florian Roth (Nextron Systems)"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
		date = "2014-01-28"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-webshells.yar#L1844-L1858"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "57b51418a799d2d016be546f399c2e9b"
		logic_hash = "4259419b4db8e6a83df6f7d258d41028f7f76b0fd2308eeadb4555066c5a2940"
		score = 70
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "<%= \"\\\\\" & oScriptNet.ComputerName & \"\\\" & oScriptNet.UserName %>" fullword
		$s7 = "Call oScript.Run (\"cmd.exe /c \" & szCMD & \" > \" & szTempFile, 0, True)" fullword

	condition:
		all of them
}
