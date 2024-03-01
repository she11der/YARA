import "pe"

rule REVERSINGLABS_Cert_Blocklist_97Df46Acb26B7C81A13Cc467B47688C8 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "68e2fdc7-61cd-5e0a-8bc7-5e0ca96271c5"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L6010-L6028"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "6f6e0e175caee83eaec2dacedaf564b642195a8815cfd0d4564f581070b0c545"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Information Civilized System Oy" and (pe.signatures[i].serial=="00:97:df:46:ac:b2:6b:7c:81:a1:3c:c4:67:b4:76:88:c8" or pe.signatures[i].serial=="97:df:46:ac:b2:6b:7c:81:a1:3c:c4:67:b4:76:88:c8") and 1602636910<=pe.signatures[i].not_after)
}
