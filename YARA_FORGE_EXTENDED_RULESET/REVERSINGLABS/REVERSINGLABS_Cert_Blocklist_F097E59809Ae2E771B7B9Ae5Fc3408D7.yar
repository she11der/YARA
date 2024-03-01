import "pe"

rule REVERSINGLABS_Cert_Blocklist_F097E59809Ae2E771B7B9Ae5Fc3408D7 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "1eed6f30-0648-5b8e-81ff-9f3af0f1c91d"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L6160-L6178"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "9e23ff26d3e1ea181e48fc23383e3717804858bc517a31ec508fa0753730c78e"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "ABEL RENOVATIONS, INC." and (pe.signatures[i].serial=="00:f0:97:e5:98:09:ae:2e:77:1b:7b:9a:e5:fc:34:08:d7" or pe.signatures[i].serial=="f0:97:e5:98:09:ae:2e:77:1b:7b:9a:e5:fc:34:08:d7") and 1602542033<=pe.signatures[i].not_after)
}
