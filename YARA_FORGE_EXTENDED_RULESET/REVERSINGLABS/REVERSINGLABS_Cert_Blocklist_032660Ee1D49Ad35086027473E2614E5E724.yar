import "pe"

rule REVERSINGLABS_Cert_Blocklist_032660Ee1D49Ad35086027473E2614E5E724 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "29cb9255-0a34-58e8-88b2-fad988c7d229"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L10972-L10988"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "8d1435d2fa70db12cde2f9098e35ca1737f5aac36bac91329b28f03aad090e90"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "sunshine.com" and pe.signatures[i].serial=="03:26:60:ee:1d:49:ad:35:08:60:27:47:3e:26:14:e5:e7:24" and 1660238245<=pe.signatures[i].not_after)
}
