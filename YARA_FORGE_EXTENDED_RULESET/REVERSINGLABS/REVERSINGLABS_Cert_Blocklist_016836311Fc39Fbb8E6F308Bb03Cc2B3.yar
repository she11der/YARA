import "pe"

rule REVERSINGLABS_Cert_Blocklist_016836311Fc39Fbb8E6F308Bb03Cc2B3 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "2c4061e8-0b8e-5c33-a746-6557449b17ed"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L11956-L11972"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "c5f6372a207d02283840e745619e93194d954eedff7bae34aadcb645b1cb78fc"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "SERVICE STREAM LIMITED" and pe.signatures[i].serial=="01:68:36:31:1f:c3:9f:bb:8e:6f:30:8b:b0:3c:c2:b3" and 1602547200<=pe.signatures[i].not_after)
}
