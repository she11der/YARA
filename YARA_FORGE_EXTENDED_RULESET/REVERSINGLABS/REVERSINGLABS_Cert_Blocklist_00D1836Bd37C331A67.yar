import "pe"

rule REVERSINGLABS_Cert_Blocklist_00D1836Bd37C331A67 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "4d99e2ee-823e-568d-88b1-48aaf6d44286"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L1216-L1234"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "8af1d10085c5be8924eb6e4ea3a9b8e936c7706d8ec43d42f24a9a293c7f9d27"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "MINDSTORM LLC" and (pe.signatures[i].serial=="00:d1:83:6b:d3:7c:33:1a:67" or pe.signatures[i].serial=="d1:83:6b:d3:7c:33:1a:67") and 1422835199<=pe.signatures[i].not_after)
}
