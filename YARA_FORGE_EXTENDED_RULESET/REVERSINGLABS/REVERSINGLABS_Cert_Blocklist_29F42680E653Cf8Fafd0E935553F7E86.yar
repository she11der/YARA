import "pe"

rule REVERSINGLABS_Cert_Blocklist_29F42680E653Cf8Fafd0E935553F7E86 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "f616e92c-ed9f-581c-aa15-970bddfb073a"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L279-L295"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "6c726e4c2933a6472d256a18ea5265660ff035d05036ab9cae3409ab5a7c7598"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Wemade Entertainment co.,Ltd" and pe.signatures[i].serial=="29:f4:26:80:e6:53:cf:8f:af:d0:e9:35:55:3f:7e:86" and 1390175999<=pe.signatures[i].not_after)
}
