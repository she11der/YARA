import "pe"

rule REVERSINGLABS_Cert_Blocklist_4E2523E76Ea455941E75Fb8240474A75 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "be5e6f35-6177-50bb-82ea-55628acda4c2"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L14314-L14330"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "e89f722345fda82fd894d34169d1463997ae1d567d46badbf3138faa04cf8fa4"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Yu Bao" and pe.signatures[i].serial=="4e:25:23:e7:6e:a4:55:94:1e:75:fb:82:40:47:4a:75" and 1476403200<=pe.signatures[i].not_after)
}
