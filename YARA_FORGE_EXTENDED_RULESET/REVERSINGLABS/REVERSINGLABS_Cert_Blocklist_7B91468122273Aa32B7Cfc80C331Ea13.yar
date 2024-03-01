import "pe"

rule REVERSINGLABS_Cert_Blocklist_7B91468122273Aa32B7Cfc80C331Ea13 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "2a949015-3b7b-5123-8df1-f2199ef636c9"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L6676-L6692"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "49d6fd8b325df4bc688275a09cee35e1040172eb6f3680aa2b6f0f3640c0782e"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "OOO KBI" and pe.signatures[i].serial=="7b:91:46:81:22:27:3a:a3:2b:7c:fc:80:c3:31:ea:13" and 1586942863<=pe.signatures[i].not_after)
}
