import "pe"

rule REVERSINGLABS_Cert_Blocklist_C81319D20C6F1F1Aec3398522189D90C : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "0a196a18-002e-58e4-bff2-83d1a67a82ce"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L11536-L11554"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "2a9f13f5e79a12f7e9d9d4a0dcaac065e1fc5167c67bc9f3fd7ba1c374b26d96"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "AMCERT,LLC" and (pe.signatures[i].serial=="00:c8:13:19:d2:0c:6f:1f:1a:ec:33:98:52:21:89:d9:0c" or pe.signatures[i].serial=="c8:13:19:d2:0c:6f:1f:1a:ec:33:98:52:21:89:d9:0c") and 1643500800<=pe.signatures[i].not_after)
}
