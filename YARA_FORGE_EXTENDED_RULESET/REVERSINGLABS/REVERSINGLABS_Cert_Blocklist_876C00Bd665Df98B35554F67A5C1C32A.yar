import "pe"

rule REVERSINGLABS_Cert_Blocklist_876C00Bd665Df98B35554F67A5C1C32A : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "830af0ac-fb01-5c6a-a7a3-2cf5c9d016fc"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L13348-L13366"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "90bde1313db78d4166e8c87e7e4111c576880922b1c983f3a842ea030d38a0da"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Lossera-M, OOO" and (pe.signatures[i].serial=="00:87:6c:00:bd:66:5d:f9:8b:35:55:4f:67:a5:c1:c3:2a" or pe.signatures[i].serial=="87:6c:00:bd:66:5d:f9:8b:35:55:4f:67:a5:c1:c3:2a") and 1493078400<=pe.signatures[i].not_after)
}
