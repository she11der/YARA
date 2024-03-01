import "pe"

rule REVERSINGLABS_Cert_Blocklist_23F537Ce13C6Cccdfd3F8Ce81Fb981Cb : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "f48b7818-5b34-5609-822a-39a2e7fb44c5"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L3434-L3450"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "d347bce3eddd0cac276a7504955f0342ae44fd93d238e514af5b1fdc208b68fc"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "ISECURE GROUP PTY LTD" and pe.signatures[i].serial=="23:f5:37:ce:13:c6:cc:cd:fd:3f:8c:e8:1f:b9:81:cb" and 1566086400<=pe.signatures[i].not_after)
}
