import "pe"

rule REVERSINGLABS_Cert_Blocklist_0A55C15F733Bf1633E9Ffae8A6E3B37D : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "32cefe84-b305-5542-a5d3-1832dcbf6d61"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L7998-L8014"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "89ca9f1c5cf0b029748528d8c5bb65f89ee05877bfdc13b4ce3d2d3e7feafb5d"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Osnova OOO" and pe.signatures[i].serial=="0a:55:c1:5f:73:3b:f1:63:3e:9f:fa:e8:a6:e3:b3:7d" and 1604016000<=pe.signatures[i].not_after)
}
