import "pe"

rule REVERSINGLABS_Cert_Blocklist_02De1Cc6C487954592F1Bf574Ca2B000 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "2a15d527-7f42-5c56-9740-9c2503a66f4f"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L11594-L11610"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "40b78005d343684d08bb93e92c51eee10e674e8deb9eec290bc9ffe3b23061b1"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Orca System" and pe.signatures[i].serial=="02:de:1c:c6:c4:87:95:45:92:f1:bf:57:4c:a2:b0:00" and 1613735394<=pe.signatures[i].not_after)
}
