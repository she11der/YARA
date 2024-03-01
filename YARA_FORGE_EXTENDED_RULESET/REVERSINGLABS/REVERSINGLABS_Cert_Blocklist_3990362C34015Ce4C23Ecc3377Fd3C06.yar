import "pe"

rule REVERSINGLABS_Cert_Blocklist_3990362C34015Ce4C23Ecc3377Fd3C06 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "453b5da2-ae26-5005-8a56-1105a960fde6"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L8036-L8052"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "0625800fcb166b56cab2e16d0d757983a6f880b68627ed8c3c38419dd9a32999"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "RZOH ApS" and pe.signatures[i].serial=="39:90:36:2c:34:01:5c:e4:c2:3e:cc:33:77:fd:3c:06" and 1606780800<=pe.signatures[i].not_after)
}
