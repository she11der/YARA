import "pe"

rule REVERSINGLABS_Cert_Blocklist_A496Bc774575C31Abec861B68C36Dcb6 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "51941c0d-a7a1-5c17-bef8-290e5db66fb7"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L7978-L7996"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "f82214f982c9972e547f77966c44e935e9de701cc9108ceca34a4fede850d243"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "ORGLE DVORSAK, d.o.o" and (pe.signatures[i].serial=="00:a4:96:bc:77:45:75:c3:1a:be:c8:61:b6:8c:36:dc:b6" or pe.signatures[i].serial=="a4:96:bc:77:45:75:c3:1a:be:c8:61:b6:8c:36:dc:b6") and 1606867200<=pe.signatures[i].not_after)
}
