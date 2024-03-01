import "pe"

rule REVERSINGLABS_Cert_Blocklist_37Ca4F66Fdcc8732992723199859886C : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "9dd87769-73d0-5299-b6ed-936703abc78e"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L16062-L16078"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "190dffc36c17c27c43337d7914683b7bab3ff18a50de5278ed2a66f04b9e395d"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Aleman Ltd" and pe.signatures[i].serial=="37:ca:4f:66:fd:cc:87:32:99:27:23:19:98:59:88:6c" and 1505952000<=pe.signatures[i].not_after)
}
