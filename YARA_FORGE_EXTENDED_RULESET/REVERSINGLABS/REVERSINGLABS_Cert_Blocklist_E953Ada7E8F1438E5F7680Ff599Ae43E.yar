import "pe"

rule REVERSINGLABS_Cert_Blocklist_E953Ada7E8F1438E5F7680Ff599Ae43E : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "2bce88d4-24e6-59e5-ae02-5284ec43cfa4"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L11900-L11918"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "7cb7d77abefd35f0756c5aa0983f7403cca4cbacd94dcc6b510c929bc96c8309"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "KULBYT LLC" and (pe.signatures[i].serial=="00:e9:53:ad:a7:e8:f1:43:8e:5f:76:80:ff:59:9a:e4:3e" or pe.signatures[i].serial=="e9:53:ad:a7:e8:f1:43:8e:5f:76:80:ff:59:9a:e4:3e") and 1614729600<=pe.signatures[i].not_after)
}
