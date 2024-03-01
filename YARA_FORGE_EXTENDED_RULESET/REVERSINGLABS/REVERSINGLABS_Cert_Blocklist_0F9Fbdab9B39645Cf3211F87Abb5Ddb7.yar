import "pe"

rule REVERSINGLABS_Cert_Blocklist_0F9Fbdab9B39645Cf3211F87Abb5Ddb7 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "ad24d2e9-ae3d-5fae-b58d-965bd1de2a99"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L567-L583"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "ba5885c7769b5ead261815880033b0df50dc4f7684fdb37398ab01bfebda0e37"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "The Motivo Group, Inc." and pe.signatures[i].serial=="0f:9f:bd:ab:9b:39:64:5c:f3:21:1f:87:ab:b5:dd:b7" and 1361318399<=pe.signatures[i].not_after)
}
