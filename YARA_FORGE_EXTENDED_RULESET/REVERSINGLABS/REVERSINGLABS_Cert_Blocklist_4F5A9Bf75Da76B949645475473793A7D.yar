import "pe"

rule REVERSINGLABS_Cert_Blocklist_4F5A9Bf75Da76B949645475473793A7D : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "90cdf420-bdfc-509a-a64f-f30710f09f3b"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L14712-L14728"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "8c58d30b1b6ef80409d9da5f5f4bc26a8818b01cc388b5966c8b68ed0e4c5a2a"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "EXEC CONTROL LIMITED" and pe.signatures[i].serial=="4f:5a:9b:f7:5d:a7:6b:94:96:45:47:54:73:79:3a:7d" and 1553817600<=pe.signatures[i].not_after)
}
