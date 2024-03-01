import "pe"

rule SIGNATURE_BASE_CN_Toolset__Xscanlib_Xscanlib_Xscanlib
{
	meta:
		description = "Detects a Chinese hacktool from a disclosed toolset - from files XScanLib.dll, XScanLib.dll, XScanLib.dll"
		author = "Florian Roth (Nextron Systems)"
		id = "c32415f4-044c-50ef-9c4c-b9327cbcef69"
		date = "2015-03-30"
		modified = "2023-12-05"
		reference = "http://qiannao.com/ls/905300366/33834c0c/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-hacktools.yar#L2959-L2980"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "f7f66f1f3ca05e60ac850fbb94c471f664d2dc8a60c09b18686c9f2937296697"
		score = 70
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		super_rule = 1
		hash0 = "af419603ac28257134e39683419966ab3d600ed2"
		hash1 = "c5cb4f75cf241f5a9aea324783193433a42a13b0"
		hash2 = "135f6a28e958c8f6a275d8677cfa7cb502c8a822"

	strings:
		$s1 = "Plug-in thread causes an exception, failed to alert user." fullword
		$s2 = "PlugGetUdpPort" fullword
		$s3 = "XScanLib.dll" fullword
		$s4 = "PlugGetTcpPort" fullword
		$s11 = "PlugGetVulnNum" fullword

	condition:
		all of them
}
