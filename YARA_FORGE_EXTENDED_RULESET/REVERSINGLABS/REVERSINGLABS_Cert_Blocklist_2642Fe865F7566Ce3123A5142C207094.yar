import "pe"

rule REVERSINGLABS_Cert_Blocklist_2642Fe865F7566Ce3123A5142C207094 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "508d9c00-c209-55b2-9a40-b62ff4d866c9"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L11086-L11102"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "1ad4adf8b05a6cc065d289e6963480d37a92712a318744a30a16aad22380f238"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "C.W.D. INSTAL LTD" and pe.signatures[i].serial=="26:42:fe:86:5f:75:66:ce:31:23:a5:14:2c:20:70:94" and 1666310400<=pe.signatures[i].not_after)
}
