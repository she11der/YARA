rule MALPEDIA_Win_Hopscotch_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "dd6bd925-f81a-5efa-b164-a58190829fd7"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.hopscotch"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.hopscotch_auto.yar#L1-L123"
		license_url = "N/A"
		logic_hash = "1aacad185595691b5a0f903be6e5a023d3d5227283438abf4c811f89adcac931"
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
		$sequence_0 = { 8b1d???????? 8d8c24a4010000 6a00 6a00 6a03 6a00 }
		$sequence_1 = { 5b 81c400010000 c3 8b8c2410010000 51 57 }
		$sequence_2 = { ffd7 56 53 8d4c2414 6a08 51 e8???????? }
		$sequence_3 = { ffd7 85c0 753c 8b35???????? ffd6 83f802 742f }
		$sequence_4 = { 7554 33f6 89b5dcfeffff 8b3d???????? 83fe05 7332 }
		$sequence_5 = { 81ec80090000 53 56 57 68???????? e8???????? }
		$sequence_6 = { 68???????? e8???????? 83c408 8d9424a8020000 }
		$sequence_7 = { 56 57 ff15???????? 85c0 7514 8d442414 }
		$sequence_8 = { c7442400ffffffff 50 c7442408ffffffff e8???????? 83c404 8d4c2400 }
		$sequence_9 = { 8b3d???????? 83c408 8d442408 50 ffd7 }

	condition:
		7 of them and filesize <1143808
}
