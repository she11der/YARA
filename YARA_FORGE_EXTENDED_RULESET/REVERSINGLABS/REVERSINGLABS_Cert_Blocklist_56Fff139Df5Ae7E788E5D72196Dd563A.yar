import "pe"

rule REVERSINGLABS_Cert_Blocklist_56Fff139Df5Ae7E788E5D72196Dd563A : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "4f34fd37-908c-573c-ba53-5ab622589e88"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L7748-L7764"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "4b58c83901605d8b43519f1bc2d4ac8dc10c794f027681378b2bee2a8ff81604"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Cifromatika LLC" and pe.signatures[i].serial=="56:ff:f1:39:df:5a:e7:e7:88:e5:d7:21:96:dd:56:3a" and 1606435200<=pe.signatures[i].not_after)
}
