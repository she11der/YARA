rule SIGNATURE_BASE_Worddoc_Powershell_Urldownloadtofile : FILE
{
	meta:
		description = "Detects Word Document with PowerShell URLDownloadToFile"
		author = "Florian Roth (Nextron Systems)"
		id = "f76c5f91-f67c-5754-b771-73383aba4d64"
		date = "2017-02-23"
		modified = "2023-12-05"
		reference = "https://www.arbornetworks.com/blog/asert/additional-insights-shamoon2/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_powershell_susp.yar#L10-L30"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "e4ea4e6092011bccfc5132186b910075361f4f77f01ae00c51c486d77a996775"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		super_rule = 1
		hash1 = "33ee8a57e142e752a9c8960c4f38b5d3ff82bf17ec060e4114f5b15d22aa902e"
		hash2 = "388b26e22f75a723ce69ad820b61dd8b75e260d3c61d74ff21d2073c56ea565d"
		hash3 = "71e584e7e1fb3cf2689f549192fe3a82fd4cd8ee7c42c15d736ebad47b028087"

	strings:
		$w1 = "Microsoft Forms 2.0 CommandButton" fullword ascii
		$w2 = "Microsoft Word 97-2003 Document" fullword ascii
		$p1 = "powershell.exe" fullword ascii
		$p2 = "URLDownloadToFile" fullword ascii

	condition:
		( uint16(0)==0xcfd0 and 1 of ($w*) and all of ($p*))
}
