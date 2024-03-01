import "pe"

rule REVERSINGLABS_Cert_Blocklist_4C687A0022C36F89E253F91D1F6954E2 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "c45a2125-dd7c-5ff1-89a8-35cbe1d924d7"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L8168-L8184"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "287c0c7a25e33e0e7def6efa23dbd2efba7c4ac3aa8f5deb8568a60a95e08bbe"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "HETCO ApS" and pe.signatures[i].serial=="4c:68:7a:00:22:c3:6f:89:e2:53:f9:1d:1f:69:54:e2" and 1606780800<=pe.signatures[i].not_after)
}
