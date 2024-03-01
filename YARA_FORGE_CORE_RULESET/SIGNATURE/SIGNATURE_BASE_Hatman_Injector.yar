rule SIGNATURE_BASE_Hatman_Injector : hatman
{
	meta:
		description = "Detects Hatman malware"
		author = "DHS/NCCIC/ICS-CERT"
		id = "b939b83d-cc4a-5998-89a7-8abf8d0b8592"
		date = "2017-12-19"
		modified = "2023-01-09"
		reference = "https://ics-cert.us-cert.gov/MAR-17-352-01-HatMan%E2%80%94Safety-System-Targeted-Malware"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_hatman.yar#L96-L106"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "19edf44bec6e1cbccefa145c5ae1bf0820729a80ac3ef1c8e7100b465b487e3c"
		score = 75
		quality = 85
		tags = ""

	condition:
		(SIGNATURE_BASE_Hatman_Memcpy_PRIVATE and SIGNATURE_BASE_Hatman_Origaddr_PRIVATE and SIGNATURE_BASE_Hatman_Loadoff_PRIVATE)
}
