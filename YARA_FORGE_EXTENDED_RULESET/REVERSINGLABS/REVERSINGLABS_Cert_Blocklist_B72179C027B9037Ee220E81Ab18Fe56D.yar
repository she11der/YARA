import "pe"

rule REVERSINGLABS_Cert_Blocklist_B72179C027B9037Ee220E81Ab18Fe56D : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "85639e74-80b0-59c6-b31b-5b3d9587b37a"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L6882-L6900"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "1416768011ff824307d112bdeecce1ad50d1f673e92bef8fddbbeb58ff98b1b1"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Planeta, TOV" and (pe.signatures[i].serial=="00:b7:21:79:c0:27:b9:03:7e:e2:20:e8:1a:b1:8f:e5:6d" or pe.signatures[i].serial=="b7:21:79:c0:27:b9:03:7e:e2:20:e8:1a:b1:8f:e5:6d") and 1603381300<=pe.signatures[i].not_after)
}
