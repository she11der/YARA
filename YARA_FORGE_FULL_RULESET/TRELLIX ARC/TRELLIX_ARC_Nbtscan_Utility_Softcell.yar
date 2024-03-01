import "pe"

rule TRELLIX_ARC_Nbtscan_Utility_Softcell : UTILITY FILE
{
	meta:
		description = "Rule to detect nbtscan utility used in the SoftCell operation"
		author = "Marc Rivero | McAfee ATR Team"
		id = "a2a8dd43-0d30-5da5-9dd3-6ba9f6473c40"
		date = "2019-06-25"
		modified = "2020-08-14"
		reference = "https://www.cybereason.com/blog/operation-soft-cell-a-worldwide-campaign-against-telecommunications-providers"
		source_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/APT/APT_Operation_SoftCell.yar#L178-L209"
		license_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/LICENSE"
		logic_hash = "6079f1363578f82fd38971d0c8f69cc156f7f678c3f2be22c5d9c3748dc80b1f"
		score = 75
		quality = 45
		tags = "UTILITY, FILE"
		rule_version = "v1"
		malware_type = "utility"
		malware_family = "Utility:W32/NbtScan"
		actor_type = "Apt"
		actor_group = "Unknown"

	strings:
		$s1 = "nbtscan 1.0.35 - 2008-04-08 - http://www.unixwiz.net/tools/" fullword ascii
		$s2 = "parse_target_cb.c" fullword ascii
		$s3 = "ranges. Ranges can be in /nbits notation (\"192.168.12.0/24\")" fullword ascii
		$s4 = "or with a range in the last octet (\"192.168.12.64-97\")" fullword ascii
		$op0 = { 52 68 d4 66 40 00 8b 85 58 ff ff ff 50 ff 15 a0 }
		$op1 = { e9 1c ff ff ff 8b 45 fc 8b e5 5d c3 cc cc cc cc }
		$op2 = { 59 59 c3 8b 65 e8 ff 75 d0 ff 15 34 60 40 00 ff }

	condition:
		uint16(0)==0x5a4d and filesize <100KB and (pe.imphash()=="2fa43c5392ec7923ababced078c2f98d" and all of them )
}
