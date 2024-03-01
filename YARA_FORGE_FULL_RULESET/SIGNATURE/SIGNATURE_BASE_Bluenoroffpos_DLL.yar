rule SIGNATURE_BASE_Bluenoroffpos_DLL
{
	meta:
		description = "Bluenoroff POS malware - hkp.dll"
		author = "Florian Roth"
		id = "d2b34b50-c7eb-5852-ba5d-734dd5038c2e"
		date = "2018-06-07"
		modified = "2023-12-05"
		reference = "http://blog.trex.re.kr/3?category=737685"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/crime_bluenoroff_pos.yar#L2-L20"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "39f23045b3e5ef60c199091b7f01ac2a3a31bcb95219aebb9a4cfd0764886f19"
		score = 75
		quality = 73
		tags = ""

	strings:
		$dll = "ksnetadsl.dll" ascii wide fullword nocase
		$exe = "xplatform.exe" ascii wide fullword nocase
		$agent = "Nimo Software HTTP Retriever 1.0" ascii wide nocase
		$log_file = "c:\\windows\\temp\\log.tmp" ascii wide nocase
		$base_addr = "%d-BaseAddr:0x%x" ascii wide nocase
		$func_addr = "%d-FuncAddr:0x%x" ascii wide nocase
		$HF_S = "HF-S(%d)" ascii wide
		$HF_T = "HF-T(%d)" ascii wide

	condition:
		5 of them
}
