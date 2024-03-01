import "pe"

rule REVERSINGLABS_Cert_Blocklist_03Bf9Ef4Cf037A2385649026C3Da9D3E : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "d7396af1-2eae-594a-9933-3d148503c0ea"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L4762-L4778"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "14196bad586b1349e6e8a1eb5621ce0d8d346ff8021c8ef80804de1533fd40d9"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "COLLECTIVE SOFTWARE INC." and pe.signatures[i].serial=="03:bf:9e:f4:cf:03:7a:23:85:64:90:26:c3:da:9d:3e" and 1595371955<=pe.signatures[i].not_after)
}
