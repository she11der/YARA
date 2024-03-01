import "pe"

rule REVERSINGLABS_Cert_Blocklist_4B03Cabe6A0481F17A2Dbeb9Aefad425 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "30108ce3-b133-5e1d-924f-7caaf390e836"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L6086-L6102"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "6986e7bd90842647ec6a168c30dca2d5ae8ae5b1c1014f966dd596a78859ac6e"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "RASSVET, OOO" and pe.signatures[i].serial=="4b:03:ca:be:6a:04:81:f1:7a:2d:be:b9:ae:fa:d4:25" and 1603230930<=pe.signatures[i].not_after)
}
