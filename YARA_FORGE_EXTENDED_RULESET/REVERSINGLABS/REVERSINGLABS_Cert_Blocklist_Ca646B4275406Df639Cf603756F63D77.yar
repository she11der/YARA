import "pe"

rule REVERSINGLABS_Cert_Blocklist_Ca646B4275406Df639Cf603756F63D77 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "b176b7f8-e3d1-593c-91c3-03e781f6ef7b"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L8186-L8204"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "a690e3f6a656835984e47d999271fe441a5fbf424208da8d5b3c9ddcef47b70e"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "SHOECORP LIMITED" and (pe.signatures[i].serial=="00:ca:64:6b:42:75:40:6d:f6:39:cf:60:37:56:f6:3d:77" or pe.signatures[i].serial=="ca:64:6b:42:75:40:6d:f6:39:cf:60:37:56:f6:3d:77") and 1605830400<=pe.signatures[i].not_after)
}
