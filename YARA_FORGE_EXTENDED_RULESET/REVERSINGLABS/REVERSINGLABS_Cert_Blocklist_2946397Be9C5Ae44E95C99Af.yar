import "pe"

rule REVERSINGLABS_Cert_Blocklist_2946397Be9C5Ae44E95C99Af : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "46bc3ade-544c-5ee1-8d5d-4b8a269120c9"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L16654-L16670"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "b7b4925482fcc47dea81eb3d84af31cc572f1b19080b98dda330b0bf6d7c80f4"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "VANKY TECHNOLOGY LIMITED" and pe.signatures[i].serial=="29:46:39:7b:e9:c5:ae:44:e9:5c:99:af" and 1476092708<=pe.signatures[i].not_after)
}
