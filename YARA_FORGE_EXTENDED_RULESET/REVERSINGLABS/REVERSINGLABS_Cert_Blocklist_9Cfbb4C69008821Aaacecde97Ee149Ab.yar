import "pe"

rule REVERSINGLABS_Cert_Blocklist_9Cfbb4C69008821Aaacecde97Ee149Ab : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "a8ba633b-fbbe-51ca-9f67-fb91ce9ac2f7"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L4344-L4362"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "d74b13eeb5d0a57c5dd3257480230c504a68a8422e77a46bb2e101abb2c7f282"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Kivaliz Prest s.r.l." and (pe.signatures[i].serial=="00:9c:fb:b4:c6:90:08:82:1a:aa:ce:cd:e9:7e:e1:49:ab" or pe.signatures[i].serial=="9c:fb:b4:c6:90:08:82:1a:aa:ce:cd:e9:7e:e1:49:ab") and 1592363914<=pe.signatures[i].not_after)
}
