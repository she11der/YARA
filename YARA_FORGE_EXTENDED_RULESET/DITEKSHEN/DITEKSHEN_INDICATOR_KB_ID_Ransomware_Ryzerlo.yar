rule DITEKSHEN_INDICATOR_KB_ID_Ransomware_Ryzerlo
{
	meta:
		description = "Detects files referencing identities associated with Ryzerlo / HiddenTear / RSJON ransomware"
		author = "ditekShen"
		id = "1e8b79dc-4a81-5126-a7a3-ad7a2e8f62bf"
		date = "2024-01-23"
		modified = "2024-01-23"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_id.yar#L312-L320"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "2d925cac74411c3e408d674e27a27ae029d39977026a79df8f90edae345a31db"
		score = 75
		quality = 73
		tags = ""

	strings:
		$s1 = "darkjon@protonmail.com" ascii wide nocase

	condition:
		any of them
}
