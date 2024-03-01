import "pe"

rule REVERSINGLABS_Cert_Blocklist_476De2F108D20B43Ba3Bae6F331Af8F1 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "5a741e6d-9b58-5536-8987-b3c36cdfcd5f"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L4216-L4232"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "e5edf3e15b2139ba6cd85f2cfea63b53f7fa36a3fd7224a4a9ccbe5de6eb6f1d"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Digiwill Limited" and pe.signatures[i].serial=="47:6d:e2:f1:08:d2:0b:43:ba:3b:ae:6f:33:1a:f8:f1" and 1588135722<=pe.signatures[i].not_after)
}
