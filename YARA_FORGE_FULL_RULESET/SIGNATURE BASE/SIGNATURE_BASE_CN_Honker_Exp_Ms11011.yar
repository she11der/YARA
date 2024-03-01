rule SIGNATURE_BASE_CN_Honker_Exp_Ms11011 : FILE
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file ms11011.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "fc092166-73cd-58f6-b034-a2fe2c5fb859"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/cn_pentestset_tools.yar#L450-L468"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "5ad7a4962acbb6b0e3b73d77385eb91feb88b386"
		logic_hash = "f92d71f163a49a158d85b821d71fd17e84e0d3deb19515ae0cf6a063a05c027b"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "\\i386\\Hello.pdb" ascii
		$s1 = "OS not supported." fullword ascii
		$s2 = ".Rich5" fullword ascii
		$s3 = "Not supported." fullword wide
		$s5 = "cmd.exe" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <100KB and all of them
}
