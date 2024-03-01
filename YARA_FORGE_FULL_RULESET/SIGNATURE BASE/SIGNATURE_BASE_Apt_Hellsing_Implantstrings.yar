rule SIGNATURE_BASE_Apt_Hellsing_Implantstrings : FILE
{
	meta:
		description = "detection for Hellsing implants"
		author = "Kaspersky Lab"
		id = "00aa5885-ae79-5d68-8587-13d3e8965630"
		date = "2015-04-07"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_hellsing_kaspersky.yar#L2-L29"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "d62dc766a40d1dc7044cc5c9f07a78d36e231b771fafb52442b26514f4c603db"
		score = 75
		quality = 85
		tags = "FILE"
		version = "1.0"
		filetype = "PE"

	strings:
		$a1 = "the file uploaded failed !"
		$a2 = "ping 127.0.0.1"
		$b1 = "the file downloaded failed !"
		$b2 = "common.asp"
		$c = "xweber_server.exe"
		$d = "action="
		$debugpath1 = "d:\\Hellsing\\release\\msger\\" nocase
		$debugpath2 = "d:\\hellsing\\sys\\xrat\\" nocase
		$debugpath3 = "D:\\Hellsing\\release\\exe\\" nocase
		$debugpath4 = "d:\\hellsing\\sys\\xkat\\" nocase
		$debugpath5 = "e:\\Hellsing\\release\\clare" nocase
		$debugpath6 = "e:\\Hellsing\\release\\irene\\" nocase
		$debugpath7 = "d:\\hellsing\\sys\\irene\\" nocase
		$e = "msger_server.dll"
		$f = "ServiceMain"

	condition:
		uint16(0)==0x5a4d and ( all of ($a*)) or ( all of ($b*)) or ($c and $d) or ( any of ($debugpath*)) or ($e and $f) and filesize <500000
}
