import "pe"

rule REVERSINGLABS_Cert_Blocklist_3A949Ef03D9Dd2D150B24B274Ff6D7B4 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "6ea47017-1296-5409-8ff2-ef69434233ff"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L15368-L15384"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "88c63a921a300e1b985d084c3ab1a2485713b4c674dafd419d092e5562f121d7"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Xin Zhou" and pe.signatures[i].serial=="3a:94:9e:f0:3d:9d:d2:d1:50:b2:4b:27:4f:f6:d7:b4" and 1474156800<=pe.signatures[i].not_after)
}
