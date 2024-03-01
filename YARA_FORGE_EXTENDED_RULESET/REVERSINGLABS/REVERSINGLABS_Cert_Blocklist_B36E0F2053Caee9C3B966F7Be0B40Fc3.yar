import "pe"

rule REVERSINGLABS_Cert_Blocklist_B36E0F2053Caee9C3B966F7Be0B40Fc3 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "8ed732ae-1c25-59fc-8ebe-50a1eb81e4a9"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L5560-L5578"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "2444c78aefdb9e8c8004598a318db016d7e781ede6da2ba3ee85316456c3e77b"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "PARTS-JEST d.o.o." and (pe.signatures[i].serial=="00:b3:6e:0f:20:53:ca:ee:9c:3b:96:6f:7b:e0:b4:0f:c3" or pe.signatures[i].serial=="b3:6e:0f:20:53:ca:ee:9c:3b:96:6f:7b:e0:b4:0f:c3") and 1600172855<=pe.signatures[i].not_after)
}
