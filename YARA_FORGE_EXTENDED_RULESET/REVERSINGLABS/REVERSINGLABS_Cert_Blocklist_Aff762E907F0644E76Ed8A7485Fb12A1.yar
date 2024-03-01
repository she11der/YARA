import "pe"

rule REVERSINGLABS_Cert_Blocklist_Aff762E907F0644E76Ed8A7485Fb12A1 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "3b3bbbdd-9c2d-5c80-a121-3e3ad13e9ac6"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L4890-L4908"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "ad05389e0eb30cb894b03842d213b8c956f66357a913c73d8d8b79f8336bf980"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Lets Start SP Z O O" and (pe.signatures[i].serial=="00:af:f7:62:e9:07:f0:64:4e:76:ed:8a:74:85:fb:12:a1" or pe.signatures[i].serial=="af:f7:62:e9:07:f0:64:4e:76:ed:8a:74:85:fb:12:a1") and 1594882330<=pe.signatures[i].not_after)
}
