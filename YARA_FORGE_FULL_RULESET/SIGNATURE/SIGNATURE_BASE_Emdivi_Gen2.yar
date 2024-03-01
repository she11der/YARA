rule SIGNATURE_BASE_Emdivi_Gen2 : FILE
{
	meta:
		description = "Detects Emdivi Malware"
		author = "Florian Roth (Nextron Systems) @Cyber0ps"
		id = "9a77c85c-84b0-5e0f-93bc-e17e2aaec095"
		date = "2015-08-20"
		modified = "2023-01-27"
		reference = "https://securelist.com/blog/research/71876/new-activity-of-the-blue-termite-apt/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_bluetermite_emdivi.yar#L62-L85"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "c40306d646c5bf8c3aff1bc697b81997b4d635ccf237775e2bea96b89f7fa001"
		score = 80
		quality = 85
		tags = "FILE"
		super_rule = 1
		hash1 = "9a351885bf5f6fec466f30021088504d96e9db10309622ed198184294717add1"
		hash2 = "a5be7cb1f37030c9f9211c71e0fbe01dae19ff0e6560c5aab393621f18a7d012"
		hash3 = "9183abb9b639699cd2ad28d375febe1f34c14679b7638d1a79edb49d920524a4"

	strings:
		$s1 = "%TEMP%\\IELogs\\" ascii
		$s2 = "MSPUB.EXE" fullword ascii
		$s3 = "%temp%\\" ascii
		$s4 = "\\NOTEPAD.EXE" ascii
		$s5 = "%4d-%02d-%02d %02d:%02d:%02d " fullword ascii
		$s6 = "INTERNET_OPEN_TYPE_PRECONFIG" fullword ascii
		$s7 = "%4d%02d%02d%02d%02d%02d" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <1300KB and 6 of them
}
