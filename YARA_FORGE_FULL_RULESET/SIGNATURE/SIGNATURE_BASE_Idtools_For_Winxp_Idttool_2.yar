rule SIGNATURE_BASE_Idtools_For_Winxp_Idttool_2 : FILE
{
	meta:
		description = "Chinese Hacktool Set - file IdtTool.sys"
		author = "Florian Roth (Nextron Systems)"
		id = "0312be49-c262-5143-abfc-02d428552b86"
		date = "2015-06-13"
		modified = "2023-12-05"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_cn_hacktools.yar#L1318-L1335"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "07feb31dd21d6f97614118b8a0adf231f8541a67"
		logic_hash = "831f42abd7374b2ca2b4115a73aae2123e2212b0854d4cc0950b8e66a28e38a3"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "\\Device\\devIdtTool" wide
		$s1 = "IoDeleteSymbolicLink" fullword ascii
		$s3 = "IoDeleteDevice" fullword ascii
		$s6 = "IoCreateSymbolicLink" fullword ascii
		$s7 = "IoCreateDevice" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <7KB and all of them
}
