import "pe"

rule REVERSINGLABS_Cert_Blocklist_0Bc0F18Da36702E302Db170D91Dc9202 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "977d9686-d811-5416-b090-d4f45d7935d0"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L16338-L16354"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "d9ee2cf63a4edb28f894ea49a5b4df9b818d5764d9a74721b1d5222f53859462"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Foresee Consulting Inc." and pe.signatures[i].serial=="0b:c0:f1:8d:a3:67:02:e3:02:db:17:0d:91:dc:92:02" and 1637712000<=pe.signatures[i].not_after)
}
