import "pe"

rule REVERSINGLABS_Cert_Blocklist_864196F01971Dbec7002B48642A7013A : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "80478430-ce01-5fae-bcaf-2b7a445bc20d"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L2412-L2430"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "a3173bb08e673caaa64ab22854840a135e891044b165bbc67733c951ec6aa991"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "WLE DESENVOLVIMENTO DE SOFTWARE E ASSESSORIA LTDA EPP" and (pe.signatures[i].serial=="00:86:41:96:f0:19:71:db:ec:70:02:b4:86:42:a7:01:3a" or pe.signatures[i].serial=="86:41:96:f0:19:71:db:ec:70:02:b4:86:42:a7:01:3a") and 1384300799<=pe.signatures[i].not_after)
}
