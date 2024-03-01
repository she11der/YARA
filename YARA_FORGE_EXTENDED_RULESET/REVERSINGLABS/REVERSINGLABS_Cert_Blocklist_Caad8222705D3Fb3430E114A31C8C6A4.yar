import "pe"

rule REVERSINGLABS_Cert_Blocklist_Caad8222705D3Fb3430E114A31C8C6A4 : INFO FILE
{
	meta:
		description = "The digital certificate has leaked."
		author = "ReversingLabs"
		id = "d95b5e25-679c-57f8-b790-8f5633a23e4b"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L1290-L1306"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "35c4f46322da4f5b9f938c1098c8e57effc8abfc03db865190c343df7b8990ea"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Adobe Systems" and pe.signatures[i].serial=="ca:ad:82:22:70:5d:3f:b3:43:0e:11:4a:31:c8:c6:a4" and 1341792000<=pe.signatures[i].not_after)
}
