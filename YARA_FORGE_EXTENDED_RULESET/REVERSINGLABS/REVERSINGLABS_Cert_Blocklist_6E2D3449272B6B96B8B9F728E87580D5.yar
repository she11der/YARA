import "pe"

rule REVERSINGLABS_Cert_Blocklist_6E2D3449272B6B96B8B9F728E87580D5 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "6975acb9-3b37-51f5-8b4d-0d1a090a18e2"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L12930-L12946"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "0155a8c71bf8426bbb980798772b04c145df5b8c4b60ff1a610a1236a47547ef"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "RADIANT, OOO" and pe.signatures[i].serial=="6e:2d:34:49:27:2b:6b:96:b8:b9:f7:28:e8:75:80:d5" and 1421107200<=pe.signatures[i].not_after)
}
