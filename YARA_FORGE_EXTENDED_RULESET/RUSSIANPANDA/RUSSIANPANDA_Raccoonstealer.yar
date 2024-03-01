rule RUSSIANPANDA_Raccoonstealer : FILE
{
	meta:
		description = "Detects Raccoon Stealer v2.3.1.1"
		author = "RussianPanda"
		id = "29f28cd5-370b-5831-8b71-a253f468f7e4"
		date = "2024-01-08"
		modified = "2024-01-08"
		reference = "https://www.esentire.com/blog/esentire-threat-intelligence-malware-analysis-raccoon-stealer-v2-0"
		source_url = "https://github.com/RussianPanda95/Yara-Rules/blob/d6b1e8ac1e4cbf548804bd84e5f63f3f426b9738/RaccoonStealer_v2/raccoonstealer_v2.3.1.1.yar#L1-L20"
		license_url = "N/A"
		hash = "c6d0d98dd43822fe12a1d785df4e391db3c92846b0473b54762fbb929de6f5cb"
		logic_hash = "ee2b39c1c2068b97e63a03330a2f9e2f12e53aaf9cfffb274acde2372a11fe45"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$s1 = {8B 0D [2] 41 00 A3 [3] 00}
		$s2 = "MachineGuid"
		$s3 = "SELECT name_on_card, card_number_encrypted, expiration_month, expiration_year FROM credit_cards"
		$s4 = "SELECT service, encrypted_token FROM token_service"
		$s5 = "&configId="
		$s6 = "machineId="

	condition:
		all of ($s*) and #s1>10 and uint16(0)==0x5A4D and filesize <5MB
}
