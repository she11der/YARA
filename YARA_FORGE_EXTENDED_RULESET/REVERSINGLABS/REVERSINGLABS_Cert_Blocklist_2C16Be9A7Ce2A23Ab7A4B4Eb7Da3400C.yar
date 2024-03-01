import "pe"

rule REVERSINGLABS_Cert_Blocklist_2C16Be9A7Ce2A23Ab7A4B4Eb7Da3400C : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "4e17aed7-fd76-549f-bcf7-84c97efc44e4"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L15314-L15330"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "917f324cbe91718efc9b2f41ef947fa8f1a501dde319936774d702d57b1e6b37"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Prince city music bar" and pe.signatures[i].serial=="2c:16:be:9a:7c:e2:a2:3a:b7:a4:b4:eb:7d:a3:40:0c" and 1371081600<=pe.signatures[i].not_after)
}
