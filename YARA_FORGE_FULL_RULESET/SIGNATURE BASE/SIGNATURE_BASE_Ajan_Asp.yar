rule SIGNATURE_BASE_Ajan_Asp
{
	meta:
		description = "Semi-Auto-generated  - file Ajan.asp.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		id = "6040fd88-b992-5110-8b37-7711ace30b1a"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-webshells.yar#L4901-L4913"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "b6f468252407efc2318639da22b08af0"
		logic_hash = "13988af864a62ca04501288d4f2d830815ab453b14cef6795fe993db1dd1a9ef"
		score = 75
		quality = 85
		tags = ""

	strings:
		$s1 = "c:\\downloaded.zip"
		$s2 = "Set entrika = entrika.CreateTextFile(\"c:\\net.vbs\", True)" fullword
		$s3 = "http://www35.websamba.com/cybervurgun/"

	condition:
		1 of them
}
