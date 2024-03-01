import "pe"

rule REVERSINGLABS_Cert_Blocklist_C7079866C0E48B01246Ba0C148E70D4D : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "2c985bd9-cb2a-553a-af63-a2a0a80cc641"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L5520-L5538"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "cc144760e0ca21fd98b55ac222db540900def61f54e9644f8cab5f711ec7bf24"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "OOO GARANT" and (pe.signatures[i].serial=="00:c7:07:98:66:c0:e4:8b:01:24:6b:a0:c1:48:e7:0d:4d" or pe.signatures[i].serial=="c7:07:98:66:c0:e4:8b:01:24:6b:a0:c1:48:e7:0d:4d") and 1588679105<=pe.signatures[i].not_after)
}
