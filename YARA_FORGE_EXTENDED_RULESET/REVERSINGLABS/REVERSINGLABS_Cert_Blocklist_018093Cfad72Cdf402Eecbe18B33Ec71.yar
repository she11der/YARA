import "pe"

rule REVERSINGLABS_Cert_Blocklist_018093Cfad72Cdf402Eecbe18B33Ec71 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "d9ab2e5c-a107-53c1-9b8d-b4625eed03b0"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L5806-L5822"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "ac398ef89e691158742598777c320832a750a7410904448778afc7ef3c63c255"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "FAT11 d.o.o." and pe.signatures[i].serial=="01:80:93:cf:ad:72:cd:f4:02:ee:cb:e1:8b:33:ec:71" and 1602000390<=pe.signatures[i].not_after)
}
