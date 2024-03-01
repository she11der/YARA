rule MALPEDIA_Win_Starsypound_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "70e37162-3a73-596a-8d7d-42b9d85b78f7"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.starsypound"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.starsypound_auto.yar#L1-L119"
		license_url = "N/A"
		logic_hash = "abf4ae91c4287e1227ba24bd55f61dc3c1250c1b8b21f760166157e29806933f"
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
		$sequence_0 = { ff15???????? 8dbc2458010000 83c9ff 33c0 }
		$sequence_1 = { 68???????? 52 e8???????? 83c420 85c0 7444 8b5304 }
		$sequence_2 = { 53 56 57 6a18 e8???????? 8bb42424040000 }
		$sequence_3 = { 8d4c2428 68???????? 51 e8???????? 56 8d542434 }
		$sequence_4 = { 8bfd 8d44240c f3a5 8b5500 8b3d???????? 6a00 }
		$sequence_5 = { 885c3438 c744241804010000 ff15???????? 8dbc2458010000 83c9ff 33c0 }
		$sequence_6 = { 50 8d4c2424 56 51 52 }
		$sequence_7 = { f3a4 885c0444 bf???????? 83c9ff 33c0 33f6 }
		$sequence_8 = { 83c40c 85c0 7e2b eb08 }
		$sequence_9 = { e8???????? 68c0270900 ff15???????? e8???????? 5f }

	condition:
		7 of them and filesize <40960
}