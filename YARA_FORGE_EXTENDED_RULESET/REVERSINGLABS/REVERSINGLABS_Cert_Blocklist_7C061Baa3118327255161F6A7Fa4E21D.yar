import "pe"

rule REVERSINGLABS_Cert_Blocklist_7C061Baa3118327255161F6A7Fa4E21D : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "f597956a-d11b-54e4-91b6-0572c0b10279"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L6752-L6770"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "4193fce69af03b3521a3cc442b762c52f8585b44fa6b0bd78b9ace171b807ed4"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "YUTAKS, OOO" and (pe.signatures[i].serial=="00:7c:06:1b:aa:31:18:32:72:55:16:1f:6a:7f:a4:e2:1d" or pe.signatures[i].serial=="7c:06:1b:aa:31:18:32:72:55:16:1f:6a:7f:a4:e2:1d") and 1599611338<=pe.signatures[i].not_after)
}
