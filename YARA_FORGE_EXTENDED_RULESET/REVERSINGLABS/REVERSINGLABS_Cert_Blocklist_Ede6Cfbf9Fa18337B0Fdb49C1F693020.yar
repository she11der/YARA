import "pe"

rule REVERSINGLABS_Cert_Blocklist_Ede6Cfbf9Fa18337B0Fdb49C1F693020 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "0389d5ba-4535-5277-9c77-bd178e66417f"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L16416-L16434"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "a7f18d0028cbc0001a196bc915b7881244a5833dd65f96dd7d2e8ab1b0622e0c"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "START ARCHITECTURE LTD" and (pe.signatures[i].serial=="00:ed:e6:cf:bf:9f:a1:83:37:b0:fd:b4:9c:1f:69:30:20" or pe.signatures[i].serial=="ed:e6:cf:bf:9f:a1:83:37:b0:fd:b4:9c:1f:69:30:20") and 1554940800<=pe.signatures[i].not_after)
}
