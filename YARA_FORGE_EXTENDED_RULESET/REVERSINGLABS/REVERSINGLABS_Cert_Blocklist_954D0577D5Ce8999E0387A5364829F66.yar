import "pe"

rule REVERSINGLABS_Cert_Blocklist_954D0577D5Ce8999E0387A5364829F66 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "70e770dd-95fd-5273-b6ee-9bb5eea30e3b"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L15386-L15404"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "84ddc08a0a55200f644778a0e3482f15e82d74c524f12a7ad91b1c3d4acfc731"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Soblosol Limited" and (pe.signatures[i].serial=="00:95:4d:05:77:d5:ce:89:99:e0:38:7a:53:64:82:9f:66" or pe.signatures[i].serial=="95:4d:05:77:d5:ce:89:99:e0:38:7a:53:64:82:9f:66") and 1543968000<=pe.signatures[i].not_after)
}
