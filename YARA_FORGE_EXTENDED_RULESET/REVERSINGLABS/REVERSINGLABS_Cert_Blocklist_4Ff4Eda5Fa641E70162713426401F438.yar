import "pe"

rule REVERSINGLABS_Cert_Blocklist_4Ff4Eda5Fa641E70162713426401F438 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "3e34aa1b-a4b1-593d-bd93-0f5913ab96b9"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L3026-L3042"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "58f5e163d9807520497ba55e42c048020f6b7653ed71f3954e7ffb490f4de0e4"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "DUHANEY LIMITED" and pe.signatures[i].serial=="4f:f4:ed:a5:fa:64:1e:70:16:27:13:42:64:01:f4:38" and 1555349604<=pe.signatures[i].not_after)
}
