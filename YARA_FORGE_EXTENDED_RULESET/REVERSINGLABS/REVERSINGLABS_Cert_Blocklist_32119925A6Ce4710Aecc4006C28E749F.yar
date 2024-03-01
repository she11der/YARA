import "pe"

rule REVERSINGLABS_Cert_Blocklist_32119925A6Ce4710Aecc4006C28E749F : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "cfd51cb8-bd04-5ede-a73e-e924815a01f0"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L4852-L4868"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "ca812cdfbb7ca984fae1e16159eb0eeb1e65767fcc6aa07eeb84966853146f9d"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Maxiol" and pe.signatures[i].serial=="32:11:99:25:a6:ce:47:10:ae:cc:40:06:c2:8e:74:9f" and 1592438400<=pe.signatures[i].not_after)
}
