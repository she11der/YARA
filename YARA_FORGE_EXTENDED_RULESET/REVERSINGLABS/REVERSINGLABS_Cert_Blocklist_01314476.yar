import "pe"

rule REVERSINGLABS_Cert_Blocklist_01314476 : INFO FILE
{
	meta:
		description = "The digital certificate has leaked."
		author = "ReversingLabs"
		id = "e0a52ad1-cebd-5ffc-953f-e0b09fc6d710"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L837-L853"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "6f2f3f3ae009fbb9ebe589fc6b640be89c4a7b734eda515f182c7e9c9ffb4779"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "DigiNotar PKIoverheid CA Overheid" and pe.signatures[i].serial=="01:31:44:76" and 1308182400<=pe.signatures[i].not_after)
}
