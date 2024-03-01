rule SIGNATURE_BASE_RAT_Pandora
{
	meta:
		description = "Detects Pandora RAT"
		author = "Kevin Breen <kevin@techanarchy.net>"
		id = "d31e4366-8911-5c9c-92dc-a99f5233c626"
		date = "2014-01-04"
		modified = "2023-12-05"
		reference = "http://malwareconfig.com/stats/Pandora"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_rats_malwareconfig.yar#L571-L599"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "d33598d0699bfb7e996047318099302c2c326e45d993a259c2bc145acf8cf54b"
		score = 75
		quality = 85
		tags = ""
		maltype = "Remote Access Trojan"
		filetype = "exe"

	strings:
		$a = "Can't get the Windows version"
		$b = "=M=Q=U=Y=]=a=e=i=m=q=u=y=}="
		$c = "JPEG error #%d" wide
		$d = "Cannot assign a %s to a %s" wide
		$g = "%s, ProgID:"
		$h = "clave"
		$i = "Shell_TrayWnd"
		$j = "melt.bat"
		$k = "\\StubPath"
		$l = "\\logs.dat"
		$m = "1027|Operation has been canceled!"
		$n = "466|You need to plug-in! Double click to install... |"
		$0 = "33|[Keylogger Not Activated!]"

	condition:
		all of them
}
