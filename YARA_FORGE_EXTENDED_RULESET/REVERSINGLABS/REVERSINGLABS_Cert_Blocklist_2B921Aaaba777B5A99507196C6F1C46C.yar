import "pe"

rule REVERSINGLABS_Cert_Blocklist_2B921Aaaba777B5A99507196C6F1C46C : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "0cb5be9e-a0b7-5785-87f3-ad097d4ab479"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L10426-L10442"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "a00eb9837f7700d83862dff2077d85c68c24621d7aacf857b42587dc37976465"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Python Software Foundation" and pe.signatures[i].serial=="2b:92:1a:aa:ba:77:7b:5a:99:50:71:96:c6:f1:c4:6c" and 1648425600<=pe.signatures[i].not_after)
}
