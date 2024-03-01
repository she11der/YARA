rule DITEKSHEN_INDICATOR_KB_ID_Ransomware_Darkside
{
	meta:
		description = "Detects files referencing identities associated with DarkSide ransomware"
		author = "ditekShen"
		id = "7b29b9b9-4657-551e-b770-880a2278ef60"
		date = "2024-01-23"
		modified = "2024-01-23"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_id.yar#L290-L299"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "3c6cdb15cad19f1db38c0fe03ecb24d5cd4861a699aa2bee0f99b8dddacc8bd1"
		score = 75
		quality = 73
		tags = ""
		hash1 = "bafa2efff234303166d663f967037dae43701e7d63d914efc8c894b3e5be9408"

	strings:
		$s1 = "breathcojunktab1987@yahoo.com" ascii wide nocase

	condition:
		any of them
}
