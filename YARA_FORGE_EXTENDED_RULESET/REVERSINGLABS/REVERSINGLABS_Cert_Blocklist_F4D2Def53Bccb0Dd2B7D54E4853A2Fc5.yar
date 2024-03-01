import "pe"

rule REVERSINGLABS_Cert_Blocklist_F4D2Def53Bccb0Dd2B7D54E4853A2Fc5 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "3c1bec34-9eac-5c7c-bb36-2e24b6ee52dc"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L4742-L4760"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "9991f44b8e984bd79269c44999481258d94bec9c21b154b63c6c30ae52344b3c"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "PETROYL GROUP, TOV" and (pe.signatures[i].serial=="00:f4:d2:de:f5:3b:cc:b0:dd:2b:7d:54:e4:85:3a:2f:c5" or pe.signatures[i].serial=="f4:d2:de:f5:3b:cc:b0:dd:2b:7d:54:e4:85:3a:2f:c5") and 1598347687<=pe.signatures[i].not_after)
}
