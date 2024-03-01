import "pe"

rule REVERSINGLABS_Cert_Blocklist_0087D60D1E2B9374Eb7A735Dce4Bbdae56 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing GovRAT malware."
		author = "ReversingLabs"
		id = "8759a40a-648e-548e-a519-bedc812aefe4"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L1562-L1580"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "d6e0d22e926a237f1cc6b71c6f8ce01e497723032c9efba1e6af7327a786b608"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "AMO-K Limited Liability Company" and (pe.signatures[i].serial=="00:87:d6:0d:1e:2b:93:74:eb:7a:73:5d:ce:4b:bd:ae:56" or pe.signatures[i].serial=="87:d6:0d:1e:2b:93:74:eb:7a:73:5d:ce:4b:bd:ae:56") and 1404172799<=pe.signatures[i].not_after)
}
