import "pe"

rule REVERSINGLABS_Cert_Blocklist_9Faf8705A3Eaef9340800Cc4Fd38597C : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "d2988928-4ef3-56bf-a407-f735756c7f81"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L7902-L7920"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "66a340f169e401705ba229d2d4548cef1a57bf1d2d320b108d12b2049b063b92"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Tekhnokod LLC" and (pe.signatures[i].serial=="00:9f:af:87:05:a3:ea:ef:93:40:80:0c:c4:fd:38:59:7c" or pe.signatures[i].serial=="9f:af:87:05:a3:ea:ef:93:40:80:0c:c4:fd:38:59:7c") and 1605744000<=pe.signatures[i].not_after)
}
