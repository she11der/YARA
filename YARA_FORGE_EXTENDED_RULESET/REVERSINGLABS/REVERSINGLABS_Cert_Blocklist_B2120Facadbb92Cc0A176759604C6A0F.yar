import "pe"

rule REVERSINGLABS_Cert_Blocklist_B2120Facadbb92Cc0A176759604C6A0F : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "8a90cc61-4d39-58eb-a102-c22d096d99ae"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L3214-L3232"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "08462b1bd3d45824aeea901a4db19365c28d8b8b0f594657df7a59250111729b"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "SLON LTD" and (pe.signatures[i].serial=="00:b2:12:0f:ac:ad:bb:92:cc:0a:17:67:59:60:4c:6a:0f" or pe.signatures[i].serial=="b2:12:0f:ac:ad:bb:92:cc:0a:17:67:59:60:4c:6a:0f") and 1554249600<=pe.signatures[i].not_after)
}
