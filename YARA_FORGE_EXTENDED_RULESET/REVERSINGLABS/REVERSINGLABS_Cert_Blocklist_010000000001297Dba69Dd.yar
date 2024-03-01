import "pe"

rule REVERSINGLABS_Cert_Blocklist_010000000001297Dba69Dd : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "f6a63e79-4dde-590f-ad65-ba9cc29ff48c"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L16528-L16544"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "bbc3e740d5043d1811ff44c7366c69192fb78c95215b30fd4f4c782812ad591c"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "ROSSO INDEX K.K." and pe.signatures[i].serial=="01:00:00:00:00:01:29:7d:ba:69:dd" and 1277713154<=pe.signatures[i].not_after)
}
