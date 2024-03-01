import "pe"

rule REVERSINGLABS_Cert_Blocklist_28C57Df09Ce7Cc3Fde2243Beb4D00101 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "63e2edab-11a4-55ba-b042-c88b6d2750a5"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L11920-L11936"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "84402dc0a58fca36424d8d6d13c60b80342bb3792f4e32e23878530264358726"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "WATER, s.r.o." and pe.signatures[i].serial=="28:c5:7d:f0:9c:e7:cc:3f:de:22:43:be:b4:d0:01:01" and 1622678400<=pe.signatures[i].not_after)
}
