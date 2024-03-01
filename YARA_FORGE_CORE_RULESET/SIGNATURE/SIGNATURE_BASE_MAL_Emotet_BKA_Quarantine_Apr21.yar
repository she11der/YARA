import "pe"

rule SIGNATURE_BASE_MAL_Emotet_BKA_Quarantine_Apr21
{
	meta:
		description = "No description has been set in the source file - Signature Base"
		author = "press inquiries <info@bka.de>, technical contact <info@mha.bka.de>"
		id = "22c27d82-00cb-5d2f-a1cc-9f8b4c60aecd"
		date = "2021-03-23"
		modified = "2023-12-05"
		reference = "https://www.bka.de/DE/IhreSicherheit/RichtigesVerhalten/StraftatenImInternet/FAQ/FAQ_node.html"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/crime_emotet.yar#L39-L52"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "cc75be5f641e21446a41bf9cc855330a612847e7e3a3be935577d33195f40d05"
		score = 75
		quality = 85
		tags = ""
		descripton = "The modified emotet binary replaces the original emotet on the system of the victim. The original emotet is copied to a quarantine for evidence-preservation."
		note = "The quarantine folder depends on the scope of the initial emotet infection (user or administrator). It is the temporary folder as returned by GetTempPathW under a filename starting with UDP as returned by GetTempFileNameW. To prevent accidental reinfection by a user, the quarantined emotet is encrypted using RC4 and a 0x20 bytes long key found at the start of the quarantined file (see $key)."
		sharing = "TLP:WHITE"

	strings:
		$key = { c3 da da 19 63 45 2c 86 77 3b e9 fd 24 64 fb b8 07 fe 12 d0 2a 48 13 38 48 68 e8 ae 91 3c ed 82 }

	condition:
		$key at 0
}
