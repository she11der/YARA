import "pe"

rule REVERSINGLABS_Cert_Blocklist_4B47D18Dbea57Abd1563Ddf89F87A6C2 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "689c1f80-3b3c-5bd7-9129-4f508cad7fb4"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L4160-L4176"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "2e464f4e9bfe0c9510a78552acffb241d2435ea9bf3f5f2501353d7f8f280d78"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "KBK, OOO" and pe.signatures[i].serial=="4b:47:d1:8d:be:a5:7a:bd:15:63:dd:f8:9f:87:a6:c2" and 1590485607<=pe.signatures[i].not_after)
}
