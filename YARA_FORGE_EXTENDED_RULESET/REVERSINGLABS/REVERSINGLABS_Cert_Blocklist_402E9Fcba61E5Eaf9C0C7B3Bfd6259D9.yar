import "pe"

rule REVERSINGLABS_Cert_Blocklist_402E9Fcba61E5Eaf9C0C7B3Bfd6259D9 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "a24e1201-4a90-5d0f-ac19-4d88a4e4cfe5"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L13294-L13310"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "1bfc2610745a98ebcf0f77504815d9d1c448697fbe407d6c2e075219b401de50"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Yongli Li" and pe.signatures[i].serial=="40:2e:9f:cb:a6:1e:5e:af:9c:0c:7b:3b:fd:62:59:d9" and 1477440000<=pe.signatures[i].not_after)
}
