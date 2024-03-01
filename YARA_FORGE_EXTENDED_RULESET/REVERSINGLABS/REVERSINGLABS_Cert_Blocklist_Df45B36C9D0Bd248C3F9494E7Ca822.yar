import "pe"

rule REVERSINGLABS_Cert_Blocklist_Df45B36C9D0Bd248C3F9494E7Ca822 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "d7d0d1c4-b341-5651-8179-4035f537ba98"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L8786-L8804"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "9c03522376b0d807cd36a0641e474d770bc3b4f8221f26d232878d2d320d072b"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "MPO STORITVE d.o.o." and (pe.signatures[i].serial=="00:df:45:b3:6c:9d:0b:d2:48:c3:f9:49:4e:7c:a8:22" or pe.signatures[i].serial=="df:45:b3:6c:9d:0b:d2:48:c3:f9:49:4e:7c:a8:22") and 1619740800<=pe.signatures[i].not_after)
}
