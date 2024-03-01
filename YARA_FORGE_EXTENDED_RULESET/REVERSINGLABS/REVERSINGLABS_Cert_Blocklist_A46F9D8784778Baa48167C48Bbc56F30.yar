import "pe"

rule REVERSINGLABS_Cert_Blocklist_A46F9D8784778Baa48167C48Bbc56F30 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "72d36a5f-6599-5456-ac67-0589e37bd035"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L17180-L17198"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "fffb6309355bc6764b0ab033db5964599c86c9a2f6d8985975a07f6b3ebb40ed"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Mapping OOO" and (pe.signatures[i].serial=="00:a4:6f:9d:87:84:77:8b:aa:48:16:7c:48:bb:c5:6f:30" or pe.signatures[i].serial=="a4:6f:9d:87:84:77:8b:aa:48:16:7c:48:bb:c5:6f:30") and 1618963200<=pe.signatures[i].not_after)
}
