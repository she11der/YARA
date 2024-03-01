import "pe"

rule REVERSINGLABS_Cert_Blocklist_03A7748A4355020A652466B5E02E07De : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "10134543-04fa-5a2f-8f77-98444ad1d7f0"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L3790-L3806"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "6dc6d0fd2b702939847981ff31c2d8103227ccd0c19f999849ff89c64a90f92f"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Teleneras MB" and pe.signatures[i].serial=="03:a7:74:8a:43:55:02:0a:65:24:66:b5:e0:2e:07:de" and 1575244801<=pe.signatures[i].not_after)
}
