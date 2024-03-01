import "pe"

rule REVERSINGLABS_Cert_Blocklist_6E3B09F43C3A0Fd53B7D600F08Fae2B5 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "66025c6e-5d85-5660-87f1-3094a536bbe2"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L16582-L16598"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "86b06519858dce4b77cb870905297a1fd1c767053fd07c0b0469eb7fc3ba6b32"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Divisible Limited" and pe.signatures[i].serial=="6e:3b:09:f4:3c:3a:0f:d5:3b:7d:60:0f:08:fa:e2:b5" and 1507248000<=pe.signatures[i].not_after)
}
