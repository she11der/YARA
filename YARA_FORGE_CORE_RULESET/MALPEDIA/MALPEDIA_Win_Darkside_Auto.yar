rule MALPEDIA_Win_Darkside_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "4e98e522-42dc-58c9-8c11-9325d3b56f3a"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.darkside"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.darkside_auto.yar#L1-L114"
		license_url = "N/A"
		logic_hash = "e40a0efe65c9a50695ac0381c3b73c18492ef0b0fce9893dbb25777c239f867f"
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
		$sequence_0 = { 8bd8 68ff000000 57 e8???????? 81c7ff000000 }
		$sequence_1 = { 85d2 7407 52 57 }
		$sequence_2 = { b9ff000000 33d2 f7f1 85c0 7418 }
		$sequence_3 = { 57 e8???????? 81c7ff000000 4b }
		$sequence_4 = { fec1 75d2 5f 5e 5a 59 5b }
		$sequence_5 = { 56 57 b9f0000000 be???????? }
		$sequence_6 = { 8b7d08 8b450c b9ff000000 33d2 f7f1 }
		$sequence_7 = { 56 57 b9f0000000 be???????? 8b4508 }
		$sequence_8 = { e8???????? 5f 5e 5a 59 5b 5d }
		$sequence_9 = { 81ea10101010 2d10101010 81eb10101010 81ef10101010 }

	condition:
		7 of them and filesize <286720
}
