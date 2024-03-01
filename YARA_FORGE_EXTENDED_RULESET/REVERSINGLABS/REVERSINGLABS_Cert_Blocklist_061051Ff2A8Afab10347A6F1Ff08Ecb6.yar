import "pe"

rule REVERSINGLABS_Cert_Blocklist_061051Ff2A8Afab10347A6F1Ff08Ecb6 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "4e23648f-9770-53ad-9c62-6e6239a02aa7"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L10334-L10350"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "db3ac3ee326c60e9abc94a2fb53d801637f044e7ab72d69e53958799e48747b7"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "TACHOPARTS SP Z O O" and pe.signatures[i].serial=="06:10:51:ff:2a:8a:fa:b1:03:47:a6:f1:ff:08:ec:b6" and 1606435200<=pe.signatures[i].not_after)
}
