rule EMBEERESEARCH_Win_Bruteratel_Syscall_Hashes_Oct_2022 : FILE
{
	meta:
		description = "Detection of Brute Ratel Badger via api hashes of Nt* functions. "
		author = "Embee_Research @ Huntress"
		id = "b82612b4-272e-5ae2-bd87-3593e55918f8"
		date = "2022-10-12"
		modified = "2023-10-18"
		reference = "https://github.com/embee-research/Yara-detection-rules/"
		source_url = "https://github.com/embee-research/Yara-detection-rules//blob/43c416f765a66a6a514addac7d484c9b652e35a7/Rules/2022/win_bruteratel_syscall_hashes_oct_2022.yar#L1-L23"
		license_url = "N/A"
		logic_hash = "e284d5568e0b5ffa0f231f98ecce13b5f5518a4e005ea001a5c89087c91eb8a1"
		score = 60
		quality = 25
		tags = "FILE"
		vendor = "Huntress"

	strings:
		$hash1 = {89 4d 39 8c}
		$hash2 = {bd ca 3b d3}
		$hash3 = {b2 c1 06 ae}
		$hash4 = {74 eb 1d 4d}

	condition:
		( uint16(0)==0x5a4d or uint16(0)==0x00e8) and (2 of ($hash*))
}
