import "pe"

rule REVERSINGLABS_Cert_Blocklist_35590Ebe4A02Dc23317D8Ce47A947A9B : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "2f72a686-c30c-572d-a78c-03747ac325b6"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L12084-L12100"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "2d4bc88943cdc8af00effab745e64e60ef662c668a0b2193c256d11831ef1554"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "OOO Largos" and pe.signatures[i].serial=="35:59:0e:be:4a:02:dc:23:31:7d:8c:e4:7a:94:7a:9b" and 1602201600<=pe.signatures[i].not_after)
}
