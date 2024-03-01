import "pe"

rule REVERSINGLABS_Cert_Blocklist_B1Da219688E51Fd0Bfac2C891D56Cbb8 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "245c582a-b168-53ce-9a3c-b291ae5bc2a0"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L3062-L3080"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "03549214940a8689213bd2eb891da1c1991627c81c8b7f26860141c397409d46"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "FIRNEEZ EUROPE LIMITED" and (pe.signatures[i].serial=="00:b1:da:21:96:88:e5:1f:d0:bf:ac:2c:89:1d:56:cb:b8" or pe.signatures[i].serial=="b1:da:21:96:88:e5:1f:d0:bf:ac:2c:89:1d:56:cb:b8") and 1542931200<=pe.signatures[i].not_after)
}
