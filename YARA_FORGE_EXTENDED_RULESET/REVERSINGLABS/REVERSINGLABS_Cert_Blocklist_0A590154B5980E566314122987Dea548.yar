import "pe"

rule REVERSINGLABS_Cert_Blocklist_0A590154B5980E566314122987Dea548 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "fd2a2165-494b-5655-a322-73f033643c74"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L10372-L10388"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "d5fdf2bc61fadf3e73bcf1695c48ebc465e614cdd2310f9e5f40648d9615afc4"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Maya logistika d.o.o." and pe.signatures[i].serial=="0a:59:01:54:b5:98:0e:56:63:14:12:29:87:de:a5:48" and 1636416000<=pe.signatures[i].not_after)
}
