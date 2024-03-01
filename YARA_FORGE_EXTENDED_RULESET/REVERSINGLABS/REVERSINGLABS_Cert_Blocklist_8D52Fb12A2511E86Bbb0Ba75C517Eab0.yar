import "pe"

rule REVERSINGLABS_Cert_Blocklist_8D52Fb12A2511E86Bbb0Ba75C517Eab0 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "1bc9d36c-381e-5359-bba4-8dd870ed9267"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L11364-L11382"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "023830ab3d71ed8ecf8f0e271c56dc267dcd000f5ff156c70d31089cd7010da8"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "VThink Software Consulting Inc." and (pe.signatures[i].serial=="00:8d:52:fb:12:a2:51:1e:86:bb:b0:ba:75:c5:17:ea:b0" or pe.signatures[i].serial=="8d:52:fb:12:a2:51:1e:86:bb:b0:ba:75:c5:17:ea:b0") and 1599177600<=pe.signatures[i].not_after)
}
