import "pe"

rule SIGNATURE_BASE_MAL_BR_Report_Thedao : FILE
{
	meta:
		description = "Detects indicator in malicious UPX packed samples"
		author = "@br_data repo"
		id = "5cc932d7-2ec6-5570-af4a-3f64b39e6db5"
		date = "2019-07-24"
		modified = "2023-12-05"
		reference = "https://github.com/br-data/2019-winnti-analyse"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_winnti_br.yar#L17-L28"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "798b092b7667462aa66590603504cb0cd1166e4ac3472627cd8cd8fdf8f0b778"
		score = 75
		quality = 60
		tags = "FILE"

	strings:
		$b = { DA A0 }

	condition:
		uint16(0)==0x5a4d and $b at pe.overlay.offset and pe.overlay.size>100
}
