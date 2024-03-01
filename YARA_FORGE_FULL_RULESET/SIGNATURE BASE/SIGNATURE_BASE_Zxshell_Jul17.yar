import "pe"

rule SIGNATURE_BASE_Zxshell_Jul17 : FILE
{
	meta:
		description = "Detects a ZxShell - CN threat group"
		author = "Florian Roth (Nextron Systems)"
		id = "1b009b20-5a19-5cac-aaaf-ca61310eab9f"
		date = "2017-07-08"
		modified = "2023-12-05"
		reference = "https://blogs.rsa.com/cat-phishing/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_zxshell.yar#L76-L101"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "2c7467417ffc8b0ed3037ace9ce4183c9d4a90d1c087a420dd3c7a9c422621b1"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "5d2a4cde9fa7c2fdbf39b2e2ffd23378d0c50701a3095d1e91e3cf922d7b0b16"

	strings:
		$x1 = "zxplug -add" fullword ascii
		$x2 = "getxxx c:\\xyz.dll" fullword ascii
		$x3 = "downfile -d c:\\windows\\update.exe" fullword ascii
		$x4 = "-fromurl http://x.x.x/x.dll" fullword ascii
		$x5 = "ping 127.0.0.1 -n 7&cmd.exe /c net start %s" fullword ascii
		$x6 = "ZXNC -e cmd.exe x.x.x.x" fullword ascii
		$x7 = "(bind a cmdshell)" fullword ascii
		$x8 = "ZXFtpServer 21 20 zx" fullword ascii
		$x9 = "ZXHttpServer" fullword ascii
		$x10 = "c:\\error.htm,.exe|c:\\a.exe,.zip|c:\\b.zip\"" fullword ascii
		$x11 = "c:\\windows\\clipboardlog.txt" fullword ascii
		$x12 = "AntiSniff -a wireshark.exe" fullword ascii
		$x13 = "c:\\windows\\keylog.txt" fullword ascii

	condition:
		( filesize <10000KB and 1 of them ) or 3 of them
}
