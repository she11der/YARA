import "pe"

rule REVERSINGLABS_Cert_Blocklist_1Ffc9825644Caf5B1F521780C5C7F42C : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "3d806d90-e029-5521-b191-6967e2691c0f"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L11346-L11362"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "1a9263c809f5633d01d4d4d0091c8dc214bad73af0eff3c9a94b33bca513f26d"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "ACTIVUS LIMITED" and pe.signatures[i].serial=="1f:fc:98:25:64:4c:af:5b:1f:52:17:80:c5:c7:f4:2c" and 1615507200<=pe.signatures[i].not_after)
}
