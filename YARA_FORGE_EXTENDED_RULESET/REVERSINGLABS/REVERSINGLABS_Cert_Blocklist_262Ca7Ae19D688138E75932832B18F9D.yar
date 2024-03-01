import "pe"

rule REVERSINGLABS_Cert_Blocklist_262Ca7Ae19D688138E75932832B18F9D : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "7151fd62-7f6c-59d7-800b-65e5b4db279b"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L6976-L6992"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "a5bb946c6199cd47a087ac26f0a996261318d1830191ea7c0e7797ff03984558"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Bisoyetutu Ltd Ltd" and pe.signatures[i].serial=="26:2c:a7:ae:19:d6:88:13:8e:75:93:28:32:b1:8f:9d" and 1616025600<=pe.signatures[i].not_after)
}
