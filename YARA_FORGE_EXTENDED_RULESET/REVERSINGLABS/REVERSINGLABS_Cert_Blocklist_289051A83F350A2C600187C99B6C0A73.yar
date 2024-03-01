import "pe"

rule REVERSINGLABS_Cert_Blocklist_289051A83F350A2C600187C99B6C0A73 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "55497d57-7d4f-50e1-85a6-e60786084e3f"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L8620-L8636"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "cd5d6f95f0cfdbf8d37ea78d061ce00512b6cb7c899152b1640673494d539dd1"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "HALL HAULAGE LTD LTD" and pe.signatures[i].serial=="28:90:51:a8:3f:35:0a:2c:60:01:87:c9:9b:6c:0a:73" and 1616716800<=pe.signatures[i].not_after)
}
