import "pe"

rule REVERSINGLABS_Cert_Blocklist_E86F46B60142092Aae81B8F6Fa3D9C7C : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "fde17cc1-a968-5134-b12b-d65cb34c086f"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L2634-L2652"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "6de16a44bc84fbf8f1d3d82526e1d7f8fd4ae3da6deaa471c77d2c8df47a14b0"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Syncode Sistemas e Tecnologia Ltda" and (pe.signatures[i].serial=="00:e8:6f:46:b6:01:42:09:2a:ae:81:b8:f6:fa:3d:9c:7c" or pe.signatures[i].serial=="e8:6f:46:b6:01:42:09:2a:ae:81:b8:f6:fa:3d:9c:7c") and 1373932799<=pe.signatures[i].not_after)
}
