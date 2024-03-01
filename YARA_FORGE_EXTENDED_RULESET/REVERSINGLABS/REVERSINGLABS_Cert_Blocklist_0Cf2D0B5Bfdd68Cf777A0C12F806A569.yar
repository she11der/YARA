import "pe"

rule REVERSINGLABS_Cert_Blocklist_0Cf2D0B5Bfdd68Cf777A0C12F806A569 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "2900c6ae-9e61-5bad-a7b4-b8eca925a1ea"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L11460-L11476"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "4d8fd52cd12f9512c0b148f9915860152f108884d29617a5fbfd62500d3a14c4"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "PROTIP d.o.o. - v ste\\xC4\\x8Daju" and pe.signatures[i].serial=="0c:f2:d0:b5:bf:dd:68:cf:77:7a:0c:12:f8:06:a5:69" and 1611705600<=pe.signatures[i].not_after)
}
