import "pe"

rule REVERSINGLABS_Cert_Blocklist_E04A344B397F752A45B128A594A3D6B5 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "b396e08c-b7dc-5498-9c68-2d8cdc5dd3d3"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L4518-L4536"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "0489577c6050f0c5d1dad5bda8c4f3c895902b932cd0324087712ccb83f14680"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Highweb Ireland Operations Limited" and (pe.signatures[i].serial=="00:e0:4a:34:4b:39:7f:75:2a:45:b1:28:a5:94:a3:d6:b5" or pe.signatures[i].serial=="e0:4a:34:4b:39:7f:75:2a:45:b1:28:a5:94:a3:d6:b5") and 1597708800<=pe.signatures[i].not_after)
}
