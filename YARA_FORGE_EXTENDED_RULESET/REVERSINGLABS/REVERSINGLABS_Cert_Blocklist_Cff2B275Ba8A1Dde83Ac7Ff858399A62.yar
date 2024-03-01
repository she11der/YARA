import "pe"

rule REVERSINGLABS_Cert_Blocklist_Cff2B275Ba8A1Dde83Ac7Ff858399A62 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "50cc539a-1f00-566d-a83f-b4d8459506d8"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L9900-L9918"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "d37e1d94048339a86b8fa173d3ab753fc5e79329b73df9fda5815cd622c57745"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "XL-FORCE ApS" and (pe.signatures[i].serial=="00:cf:f2:b2:75:ba:8a:1d:de:83:ac:7f:f8:58:39:9a:62" or pe.signatures[i].serial=="cf:f2:b2:75:ba:8a:1d:de:83:ac:7f:f8:58:39:9a:62") and 1636111842<=pe.signatures[i].not_after)
}
