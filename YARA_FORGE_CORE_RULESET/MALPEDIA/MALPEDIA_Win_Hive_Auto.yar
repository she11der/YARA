rule MALPEDIA_Win_Hive_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "d6a0e69c-8ba3-5e7b-a7ea-75f1727a32de"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.hive"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.hive_auto.yar#L1-L183"
		license_url = "N/A"
		logic_hash = "6114f2e9f03828db87c71adf2ad1d3eed20f57d01fa9bb999ecd2843927df4e0"
		score = 75
		quality = 73
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
		$sequence_0 = { 31c0 b91d000000 31d2 31db }
		$sequence_1 = { b807000000 b9d4000000 31d2 31db }
		$sequence_2 = { 89c2 e8???????? b801000000 e8???????? }
		$sequence_3 = { 31c9 31d2 bb54000000 31f6 }
		$sequence_4 = { 89d1 e8???????? b802000000 e8???????? }
		$sequence_5 = { 31c9 31d2 bb08000000 becb000000 31ff }
		$sequence_6 = { 89d0 b90d000000 e8???????? b90d000000 }
		$sequence_7 = { 31db 31ff eb31 31c0 }
		$sequence_8 = { 31ff e8???????? 833d????????00 7511 }
		$sequence_9 = { 89d1 e8???????? b901000000 e8???????? }
		$sequence_10 = { 81c4b0000000 c3 e8???????? 90 }
		$sequence_11 = { 31c9 31d2 bb09000000 bee0000000 }
		$sequence_12 = { 31c0 eb17 0fb6940496000000 0fb674041c 31d6 }
		$sequence_13 = { 01c1 83c101 83f90c 0f820fffffff }
		$sequence_14 = { 01c1 c1e106 400fb6d6 01ca }
		$sequence_15 = { 01c8 c1e006 400fb6cf 01c1 }
		$sequence_16 = { 01c1 c1e106 0fb6c2 01c8 }
		$sequence_17 = { 01c2 b8ffffff03 21c5 21c3 }
		$sequence_18 = { 01c0 4000f8 0fb6c0 48898424b0000000 }
		$sequence_19 = { 01ca c1e206 0fb6c3 01d0 }
		$sequence_20 = { 01c8 89c1 c1e91f ffc9 }

	condition:
		7 of them and filesize <7946240
}
