import "pe"

rule REVERSINGLABS_Cert_Blocklist_6D633Df9Bb6015Fc3Ecea99Dff309Ee7 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "b85bf9c5-f438-5973-83ab-926e44cf2298"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L13620-L13636"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "84e2f427ee79b47db8d0e5f1e2217a7e1c1ea64047e01b4ea6db69f529501f36"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Yuanyuan Zhang" and pe.signatures[i].serial=="6d:63:3d:f9:bb:60:15:fc:3e:ce:a9:9d:ff:30:9e:e7" and 1474156800<=pe.signatures[i].not_after)
}
