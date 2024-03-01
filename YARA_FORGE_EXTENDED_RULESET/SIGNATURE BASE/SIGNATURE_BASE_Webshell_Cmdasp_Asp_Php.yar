rule SIGNATURE_BASE_Webshell_Cmdasp_Asp_Php
{
	meta:
		description = "PHP Webshells Github Archive - file CmdAsp.asp.php.txt"
		author = "Florian Roth (Nextron Systems)"
		id = "184b1731-31a9-5040-aa25-d145e8064758"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-webshells.yar#L6185-L6204"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "cb18e1ac11e37e236e244b96c2af2d313feda696"
		logic_hash = "0fd9c7e83ad9ddf5cf88f1d1573324d9f24ae03a1951446fe11c116fd0cf4932"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "szTempFile = \"C:\\\" & oFileSys.GetTempName( )" fullword
		$s4 = "' Author: Maceo <maceo @ dogmile.com>" fullword
		$s5 = "' -- Use a poor man's pipe ... a temp file -- '" fullword
		$s6 = "' --------------------o0o--------------------" fullword
		$s8 = "' File: CmdAsp.asp" fullword
		$s11 = "<-- CmdAsp.asp -->" fullword
		$s14 = "Call oScript.Run (\"cmd.exe /c \" & szCMD & \" > \" & szTempFile, 0, True)" fullword
		$s16 = "Set oScriptNet = Server.CreateObject(\"WSCRIPT.NETWORK\")" fullword
		$s19 = "<%= \"\\\\\" & oScriptNet.ComputerName & \"\\\" & oScriptNet.UserName %>" fullword

	condition:
		4 of them
}
