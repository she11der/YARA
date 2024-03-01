import "pe"

rule REVERSINGLABS_Cert_Blocklist_2E07A8D6E3B25Ae010C8Ed2C4Ab0Fb37 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "39d23cbf-862f-5a3d-9e30-b3f0929963d5"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L10588-L10604"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "bad2144c9cde02a75fa968e3c24178f3ba73b0addb2b4967f24733b933e0eeb6"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Emurasoft, Inc." and pe.signatures[i].serial=="2e:07:a8:d6:e3:b2:5a:e0:10:c8:ed:2c:4a:b0:fb:37" and 1650499200<=pe.signatures[i].not_after)
}
