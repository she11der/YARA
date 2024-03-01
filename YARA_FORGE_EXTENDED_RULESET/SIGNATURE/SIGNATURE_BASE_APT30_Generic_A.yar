rule SIGNATURE_BASE_APT30_Generic_A : FILE
{
	meta:
		description = "FireEye APT30 Report Sample"
		author = "Florian Roth (Nextron Systems)"
		id = "6b851d94-d3bd-5c76-8fd0-adb42b3fab73"
		date = "2015-04-13"
		modified = "2023-12-05"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_apt30_backspace.yar#L409-L429"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "c20660a8a55c6c6cb058fb233e0b29e1e4be2683181dbdfb06e17037d0ed8c31"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "9f49aa1090fa478b9857e15695be4a89f8f3e594"
		hash2 = "396116cfb51cee090822913942f6ccf81856c2fb"
		hash3 = "fef9c3b4b35c226501f7d60816bb00331a904d5b"
		hash4 = "7c9a13f1fdd6452fb6d62067f958bfc5fec1d24e"
		hash5 = "5257ba027abe3a2cf397bfcae87b13ab9c1e9019"

	strings:
		$s5 = "WPVWhhiA" fullword ascii
		$s6 = "VPWVhhiA" fullword ascii
		$s11 = "VPhhiA" fullword ascii
		$s12 = "uUhXiA" fullword ascii

	condition:
		filesize <100KB and uint16(0)==0x5A4D and all of them
}
