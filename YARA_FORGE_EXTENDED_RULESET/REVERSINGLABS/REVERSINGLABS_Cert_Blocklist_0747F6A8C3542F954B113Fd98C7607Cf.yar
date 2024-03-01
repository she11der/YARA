import "pe"

rule REVERSINGLABS_Cert_Blocklist_0747F6A8C3542F954B113Fd98C7607Cf : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "de5fbb40-7d41-5f3e-97c9-a6882c19ebb5"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L14584-L14600"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "9d5e5c98f3ef372532cfc4f544d5d3f620dc2e49d8b6e1c96df29d2a38042019"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Xin Zhou" and pe.signatures[i].serial=="07:47:f6:a8:c3:54:2f:95:4b:11:3f:d9:8c:76:07:cf" and 1474329600<=pe.signatures[i].not_after)
}
