import "pe"

rule REVERSINGLABS_Cert_Blocklist_7473D95405D2B0B3A8F28785Ce6E74Ca : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "7f44b9d8-917b-5fc4-9651-cce89358e415"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L1888-L1904"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "e15b990b13617017ca2d1f8caf03d8ff3785ca9b860bf11f81af5dadf17a9be5"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Dmitrij Emelyanov" and pe.signatures[i].serial=="74:73:d9:54:05:d2:b0:b3:a8:f2:87:85:ce:6e:74:ca" and 1453939199<=pe.signatures[i].not_after)
}
