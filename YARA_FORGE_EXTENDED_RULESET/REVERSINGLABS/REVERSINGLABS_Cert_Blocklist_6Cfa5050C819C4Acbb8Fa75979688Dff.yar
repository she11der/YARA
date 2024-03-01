import "pe"

rule REVERSINGLABS_Cert_Blocklist_6Cfa5050C819C4Acbb8Fa75979688Dff : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "f91ecc17-7406-552a-8864-c9e1657a5ca9"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L6290-L6308"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "cffc234be78446191dd5f5990db9f17c7e28eeaa3e16f1eb8ad4ed1e58fdc25e"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Elite Web Development Ltd." and (pe.signatures[i].serial=="00:6c:fa:50:50:c8:19:c4:ac:bb:8f:a7:59:79:68:8d:ff" or pe.signatures[i].serial=="6c:fa:50:50:c8:19:c4:ac:bb:8f:a7:59:79:68:8d:ff") and 1600176940<=pe.signatures[i].not_after)
}
