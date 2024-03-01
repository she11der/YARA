rule SIGNATURE_BASE_Asp_Shell : FILE
{
	meta:
		description = "Laudanum Injector Tools - file shell.asp"
		author = "Florian Roth (Nextron Systems)"
		id = "3ae27254-325a-5358-b5aa-ab24b43ad5a6"
		date = "2015-06-22"
		modified = "2023-12-05"
		reference = "http://laudanum.inguardians.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_laudanum_webshells.yar#L47-L66"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "8bf1ff6f8edd45e3102be5f8a1fe030752f45613"
		logic_hash = "af9c5cf7125e1210761e720c5f30527ac6345b5029b087807309000a29b67f6e"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "<form action=\"shell.asp\" method=\"POST\" name=\"shell\">" fullword ascii
		$s2 = "%ComSpec% /c dir" fullword ascii
		$s3 = "Set objCmd = wShell.Exec(cmd)" fullword ascii
		$s4 = "Server.ScriptTimeout = 180" fullword ascii
		$s5 = "cmd = Request.Form(\"cmd\")" fullword ascii
		$s6 = "' ***  http://laudanum.secureideas.net" fullword ascii
		$s7 = "Dim wshell, intReturn, strPResult" fullword ascii

	condition:
		filesize <15KB and 4 of them
}
