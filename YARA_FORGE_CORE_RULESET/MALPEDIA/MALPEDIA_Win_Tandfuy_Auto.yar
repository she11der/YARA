rule MALPEDIA_Win_Tandfuy_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "38730032-1555-50d4-b759-37b770d675ac"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.tandfuy"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.tandfuy_auto.yar#L1-L127"
		license_url = "N/A"
		logic_hash = "7ea6bc2b0de15e30b85cc41fe9dae28b9e373e31fa36302d55838d87545cc73b"
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
		$sequence_0 = { 52 8b942458010000 25ff000000 81e1ff000000 50 }
		$sequence_1 = { f68221eb6e0004 7403 40 ff01 ff01 40 e9???????? }
		$sequence_2 = { e8???????? 83c404 85c0 0f8440010000 b93e000000 33c0 8dbdd8f9ffff }
		$sequence_3 = { 8bec 8b4508 ff3485a0d66e00 ff15???????? 5d c3 55 }
		$sequence_4 = { 6a00 51 6a02 52 56 ff15???????? 56 }
		$sequence_5 = { 52 33c9 8a4801 51 33d2 8a10 }
		$sequence_6 = { f3ab 8dbc2474020000 83c9ff f2ae f7d1 2bf9 8bc1 }
		$sequence_7 = { 7562 b8???????? 81c49c000000 c3 83f806 7551 }
		$sequence_8 = { 8d95e8feffff 8b7d08 83c9ff 33c0 f2ae f7d1 }
		$sequence_9 = { 6800000080 56 f3ab ff15???????? 8bd8 }

	condition:
		7 of them and filesize <155648
}
