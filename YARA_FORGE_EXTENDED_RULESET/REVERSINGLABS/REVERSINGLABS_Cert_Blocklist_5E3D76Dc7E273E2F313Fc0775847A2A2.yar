import "pe"

rule REVERSINGLABS_Cert_Blocklist_5E3D76Dc7E273E2F313Fc0775847A2A2 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing Sakula and Derusbi malware."
		author = "ReversingLabs"
		id = "93707307-a250-526d-a3d4-32ed5d2a63a6"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L2068-L2084"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "b943057fc3e97cfccadb4b8f61289a93b659aacf2a40217fcf519d4882e70708"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "NexG" and pe.signatures[i].serial=="5e:3d:76:dc:7e:27:3e:2f:31:3f:c0:77:58:47:a2:a2" and 1372723199<=pe.signatures[i].not_after)
}
