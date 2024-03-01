import "pe"

rule REVERSINGLABS_Cert_Blocklist_Fd7B7A8678A67181A54Bc7499Eba44Da : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "d6456cb6-e950-54be-a7f4-5c1d622c6aab"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L3100-L3118"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "f1e26ea26890043be2c8b9c35ba2e6758b60fe173f00bf4c77cc5289ce0d5600"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "IMRAN IT SERVICES LTD" and (pe.signatures[i].serial=="00:fd:7b:7a:86:78:a6:71:81:a5:4b:c7:49:9e:ba:44:da" or pe.signatures[i].serial=="fd:7b:7a:86:78:a6:71:81:a5:4b:c7:49:9e:ba:44:da") and 1548028800<=pe.signatures[i].not_after)
}
