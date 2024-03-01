import "pe"

rule REVERSINGLABS_Cert_Blocklist_A2A0Ba281262Acce7A00119E25564386 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "ab0c7b78-5e7e-5cb9-ae61-d88f3f8d9684"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L9784-L9802"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "f5e3c16f6caaf5f3152d90dc48895d0bbcdb296c368beeebb96157f03a8ded40"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Sopiteks LLC" and (pe.signatures[i].serial=="00:a2:a0:ba:28:12:62:ac:ce:7a:00:11:9e:25:56:43:86" or pe.signatures[i].serial=="a2:a0:ba:28:12:62:ac:ce:7a:00:11:9e:25:56:43:86") and 1631908320<=pe.signatures[i].not_after)
}
