rule MALPEDIA_Elf_Persirai_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "a8d888a8-efae-5fcd-8298-ba3399d89281"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/elf.persirai"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/elf.persirai_auto.yar#L1-L132"
		license_url = "N/A"
		logic_hash = "091433f152a0a1932173079b7afa5457b62363ecd6425f8d1d7de8df73a8fbb4"
		score = 75
		quality = 75
		tags = "FILE"
		version = "1"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"

	strings:
		$sequence_0 = { c3 c3 53 83ec08 e8???????? 31d2 8b5c2414 }
		$sequence_1 = { 8b5c2410 837c241400 740b 83ec0c ff7304 ff13 83c410 }
		$sequence_2 = { 50 52 e8???????? 58 8d8424d8170000 50 e8???????? }
		$sequence_3 = { 8d4400e0 50 e8???????? 89c2 a3???????? 83c410 83c8ff }
		$sequence_4 = { 817c2414ff030000 0f8770030000 8b442414 c1e004 83b888a2050800 0f85df000000 8b0d???????? }
		$sequence_5 = { c7042408000000 50 a1???????? 6a1a 6a01 50 e8???????? }
		$sequence_6 = { 83c418 5b c3 81ecac000000 31d2 a1???????? }
		$sequence_7 = { 85c0 74cb e8???????? 52 52 8b00 }
		$sequence_8 = { c680b901000000 8b45f0 e8???????? 89f0 8b55f0 e8???????? 8b45f0 }
		$sequence_9 = { 83c004 89442418 e9???????? bf0a000000 e9???????? bf10000000 e9???????? }

	condition:
		7 of them and filesize <229376
}
