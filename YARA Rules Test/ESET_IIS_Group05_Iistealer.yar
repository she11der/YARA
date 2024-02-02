rule ESET_IIS_Group05_Iistealer
{
	meta:
		description = "Detects Group 5 native IIS malware family (IIStealer)"
		author = "ESET Research"
		id = "598ec6b2-0349-5da7-acad-72ef2468b927"
		date = "2021-08-04"
		modified = "2021-08-04"
		reference = "https://github.com/eset/malware-ioc/"
		source_url = "https://github.com/eset/malware-ioc/blob/089121b074e13feca43c9c6898cc901a3d637e42/badiis/badiis.yar#L201-L232"
		license_url = "https://github.com/eset/malware-ioc/blob/089121b074e13feca43c9c6898cc901a3d637e42/LICENSE"
		logic_hash = "5dff445121fda59df805d6fcb5db3f8f8e52a6e63e2da2a6875f8c9ad9cafc72"
		score = 75
		quality = 80
		tags = ""
		license = "BSD 2-Clause"
		version = "1"

	strings:
		$s1 = "tojLrGzFMbcDTKcH" ascii wide
		$s2 = "4vUOj3IutgtrpVwh" ascii wide
		$s3 = "SoUnRCxgREXMu9bM" ascii wide
		$s4 = "9Zr1Z78OkgaXj1Xr" ascii wide
		$s5 = "cache.txt" ascii wide
		$s6 = "/checkout/checkout.aspx" ascii wide
		$s7 = "/checkout/Payment.aspx" ascii wide
		$s8 = "/privacy.aspx"
		$s9 = "X-IIS-Data"
		$s10 = "POST"
		$s11 = {C7 ?? CF 2F 00 63 00 C7 ?? D3 68 00 65 00 C7 ?? D7 63 00 6B 00 C7 ?? DB 6F 00 75 00 C7 ?? DF 74 00 2F 00 C7 ?? E3 63 00 68 00 C7 ?? E7 65 00 63 00 C7 ?? EB 6B 00 6F 00 C7 ?? EF 75 00 74 00 C7 ?? F3 2E 00 61 00 C7 ?? F7 73 00 70 00 C7 ?? FB 78 00 00 00}
		$s12 = {C7 ?? AF 2F 00 70 00 C7 ?? B3 72 00 69 00 C7 ?? B7 76 00 61 00 C7 ?? BB 63 00 79 00 C7 ?? BF 2E 00 61 00 C7 ?? C3 73 00 70 00 C7 ?? C7 78 00 00 00}

	condition:
		ESET_IIS_Native_Module_PRIVATE and 3 of ($s*)
}