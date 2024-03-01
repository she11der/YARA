rule SIGNATURE_BASE_Webshell_Insomnia
{
	meta:
		description = "Insomnia Webshell - file InsomniaShell.aspx"
		author = "Florian Roth (Nextron Systems)"
		id = "62ed3695-9ab8-54d4-a9d2-b6270c56ccfb"
		date = "2014-12-09"
		modified = "2023-12-05"
		reference = "http://www.darknet.org.uk/2014/12/insomniashell-asp-net-reverse-shell-bind-shell/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-webshells.yar#L9092-L9113"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "e0cfb2ffaa1491aeaf7d3b4ee840f72d42919d22"
		logic_hash = "d170c60f94092a38ba4af92283debd059eef2e4c683fd7737ffd60d1a2581d9c"
		score = 80
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "Response.Write(\"- Failed to create named pipe:\");" fullword ascii
		$s1 = "Response.Output.Write(\"+ Sending {0}<br>\", command);" fullword ascii
		$s2 = "String command = \"exec master..xp_cmdshell 'dir > \\\\\\\\127.0.0.1" ascii
		$s3 = "Response.Write(\"- Error Getting User Info<br>\");" fullword ascii
		$s4 = "string lpCommandLine, ref SECURITY_ATTRIBUTES lpProcessAttributes," fullword ascii
		$s5 = "[DllImport(\"Advapi32.dll\", SetLastError = true)]" fullword ascii
		$s9 = "username = DumpAccountSid(tokUser.User.Sid);" fullword ascii
		$s14 = "//Response.Output.Write(\"Opened process PID: {0} : {1}<br>\", p" ascii

	condition:
		3 of them
}
