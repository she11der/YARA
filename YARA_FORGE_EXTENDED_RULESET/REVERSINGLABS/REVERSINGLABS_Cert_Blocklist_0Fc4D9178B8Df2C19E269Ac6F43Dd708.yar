import "pe"

rule REVERSINGLABS_Cert_Blocklist_0Fc4D9178B8Df2C19E269Ac6F43Dd708 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "b336ff6c-d94e-5715-bb97-6b60cda90911"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L12818-L12834"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "41dfe37b464d337268a8bb0e23124df7b50ab966038e8ad33bda81a4d86040ca"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "PK Partnership, OOO" and pe.signatures[i].serial=="0f:c4:d9:17:8b:8d:f2:c1:9e:26:9a:c6:f4:3d:d7:08" and 1466553600<=pe.signatures[i].not_after)
}
