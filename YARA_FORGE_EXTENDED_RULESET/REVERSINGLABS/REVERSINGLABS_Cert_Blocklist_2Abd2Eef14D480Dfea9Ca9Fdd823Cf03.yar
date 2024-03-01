import "pe"

rule REVERSINGLABS_Cert_Blocklist_2Abd2Eef14D480Dfea9Ca9Fdd823Cf03 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "d6cb1371-113d-5155-aed2-c575321f0973"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L8434-L8450"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "2dfc220c44d3dda28a253e5115ae9a087b6ddbf1a7ca1e9bcae5bd9ac5b2e1a0"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "BE SOL d.o.o." and pe.signatures[i].serial=="2a:bd:2e:ef:14:d4:80:df:ea:9c:a9:fd:d8:23:cf:03" and 1611100800<=pe.signatures[i].not_after)
}
