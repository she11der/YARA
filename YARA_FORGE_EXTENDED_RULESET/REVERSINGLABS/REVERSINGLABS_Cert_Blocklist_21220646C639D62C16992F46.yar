import "pe"

rule REVERSINGLABS_Cert_Blocklist_21220646C639D62C16992F46 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "b80b1832-6bfa-555b-8462-cd17f9e5e0e1"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L16600-L16616"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "87202c29867e6410d59c1e3b5ab09a24ebac5c68c61d7b932b91a91dcf3707e2"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Sivi Technology Limited" and pe.signatures[i].serial=="21:22:06:46:c6:39:d6:2c:16:99:2f:46" and 1466130984<=pe.signatures[i].not_after)
}
