rule SIGNATURE_BASE_Irontiger_Aspxspy : HIGHVOL
{
	meta:
		description = "ASPXSpy detection. It might be used by other fraudsters"
		author = "Cyber Safety Solutions, Trend Micro"
		id = "3010fcb9-0dbf-59ef-90ce-01d922a95f2d"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "http://goo.gl/T5fSJC"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_irontiger_trendmicro.yar#L1-L13"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "6b5830d3fd6aa346b27788cd4abd581b4724fecc4e880b14dd7b1dd27ef1eea3"
		score = 75
		quality = 85
		tags = ""

	strings:
		$str2 = "IIS Spy" wide ascii
		$str3 = "protected void DGCoW(object sender,EventArgs e)" wide ascii

	condition:
		any of ($str*)
}
