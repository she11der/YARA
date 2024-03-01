import "pe"

rule REVERSINGLABS_Cert_Blocklist_Ffff2Ce862378B26440Df49Ca9175B70 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "d5d1e84d-328f-53ac-adb6-3824fa77a47d"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L5194-L5212"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "8ed7b0643b07ce4954f570157e1534ee1ed647717cce00fe7f2b572c9b5d0042"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "F & A.TIM d.o.o." and (pe.signatures[i].serial=="00:ff:ff:2c:e8:62:37:8b:26:44:0d:f4:9c:a9:17:5b:70" or pe.signatures[i].serial=="ff:ff:2c:e8:62:37:8b:26:44:0d:f4:9c:a9:17:5b:70") and 1576195200<=pe.signatures[i].not_after)
}
