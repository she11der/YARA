import "pe"

rule REVERSINGLABS_Cert_Blocklist_0B1926A5E8Ae50A0Efa504F005F93869 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "ce437144-0f99-5c41-8d15-edeceb34de4d"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L6254-L6270"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "1cbdf39a873c83d2b55723215fb4930a3ce23b6cab2d71a6cd5f16b2721e30f9"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Nordkod LLC" and pe.signatures[i].serial=="0b:19:26:a5:e8:ae:50:a0:ef:a5:04:f0:05:f9:38:69" and 1600650000<=pe.signatures[i].not_after)
}
