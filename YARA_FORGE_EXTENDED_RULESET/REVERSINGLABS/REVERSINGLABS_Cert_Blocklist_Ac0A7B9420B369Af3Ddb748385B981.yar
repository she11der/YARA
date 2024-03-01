import "pe"

rule REVERSINGLABS_Cert_Blocklist_Ac0A7B9420B369Af3Ddb748385B981 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "82d6c0f5-80d1-5003-a5c9-9eadd9654460"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L7670-L7688"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "2bc31eaa64be487cb85873a64b7462d90d1c28839def070ce5db7ae555383421"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "OOO Tochka" and (pe.signatures[i].serial=="00:ac:0a:7b:94:20:b3:69:af:3d:db:74:83:85:b9:81" or pe.signatures[i].serial=="ac:0a:7b:94:20:b3:69:af:3d:db:74:83:85:b9:81") and 1604620800<=pe.signatures[i].not_after)
}
