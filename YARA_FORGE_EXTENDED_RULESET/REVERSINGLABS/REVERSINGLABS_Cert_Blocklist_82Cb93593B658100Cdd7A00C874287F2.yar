import "pe"

rule REVERSINGLABS_Cert_Blocklist_82Cb93593B658100Cdd7A00C874287F2 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "85df653a-a4a3-5d0e-86f4-cad0249cd3d3"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L6558-L6576"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "c77881e0365c9fc398097d0b6e077330a5f0fcbb53279bfde96b3c01df914c55"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Sportsonline24 B.V." and (pe.signatures[i].serial=="00:82:cb:93:59:3b:65:81:00:cd:d7:a0:0c:87:42:87:f2" or pe.signatures[i].serial=="82:cb:93:59:3b:65:81:00:cd:d7:a0:0c:87:42:87:f2") and 1605117874<=pe.signatures[i].not_after)
}
