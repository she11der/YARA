import "pe"

rule REVERSINGLABS_Cert_Blocklist_6E7Cc176062D91225Cfdcbdf5B5F0Ea5 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "cb6ae82f-ac1e-528d-aa17-6dc14019793c"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L14204-L14220"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "1d2ffa7ec3559061432c2aff23f568cb580fb9093d0af7d8a6a0b91add89c9cc"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "SG Internet" and pe.signatures[i].serial=="6e:7c:c1:76:06:2d:91:22:5c:fd:cb:df:5b:5f:0e:a5" and 1317945600<=pe.signatures[i].not_after)
}
