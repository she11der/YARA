import "pe"

rule REVERSINGLABS_Cert_Blocklist_067Dffc5E3026Eb4C62971C98Ac8A900 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "9b9771bb-c2a4-5a6e-8fdb-b3e98f62f9b1"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L3044-L3060"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "2b7c4cded14afd8ba3feabb6debaa1317917b811b44e22aa8a0b3ea00d689141"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "DVERI FADO, TOV" and pe.signatures[i].serial=="06:7d:ff:c5:e3:02:6e:b4:c6:29:71:c9:8a:c8:a9:00" and 1552176000<=pe.signatures[i].not_after)
}
