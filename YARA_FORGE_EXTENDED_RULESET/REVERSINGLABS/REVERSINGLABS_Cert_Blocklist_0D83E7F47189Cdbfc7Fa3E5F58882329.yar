import "pe"

rule REVERSINGLABS_Cert_Blocklist_0D83E7F47189Cdbfc7Fa3E5F58882329 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "d6bda332-06fc-5b1a-99fb-fc9578dc5326"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L8246-L8262"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "b344f9fd6d8378b7d77a34b14c5f37eea253f3d13a8eb0777925f195fb3cf502"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "THE WIZARD GIFT CORPORATION" and pe.signatures[i].serial=="0d:83:e7:f4:71:89:cd:bf:c7:fa:3e:5f:58:88:23:29" and 1605830400<=pe.signatures[i].not_after)
}
