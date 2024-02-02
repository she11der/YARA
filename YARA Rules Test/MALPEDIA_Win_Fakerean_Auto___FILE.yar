rule MALPEDIA_Win_Fakerean_Auto___FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "a7ea6f88-76f7-54f5-a9b5-14fd4ef8d3d9"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.fakerean"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.fakerean_auto.yar#L1-L131"
		license_url = "N/A"
		logic_hash = "7dfee10ceca58c69279376a54d184530389bbd0c9b8b6dd9a398c5796de2f6f3"
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
		$sequence_0 = { 752e 8945fc eb29 395dfc 7524 57 8bce }
		$sequence_1 = { 49 6a01 ff750c 50 57 ff7514 40 }
		$sequence_2 = { ff15???????? 3d14050000 74e5 ff7508 56 57 ff15???????? }
		$sequence_3 = { ff7508 ff15???????? 3bc3 0f8495000000 8b400c 8b00 }
		$sequence_4 = { 59 3bc3 7419 8d5010 e8???????? 8945e0 3bc3 }
		$sequence_5 = { ff35???????? ff15???????? 6800000500 6aec ff35???????? ff15???????? 680000cf06 }
		$sequence_6 = { 741a 81fe00020000 7d12 56 8bc7 e8???????? }
		$sequence_7 = { 8b4df0 6bc018 6bc918 8b4c190c 2b4c1804 f7df }
		$sequence_8 = { f7d8 1bc0 25bfe0ffff 05401f0000 50 ff35???????? ff15???????? }
		$sequence_9 = { 8d45f0 50 8d450c 50 ff15???????? 85c0 7431 }

	condition:
		7 of them and filesize <4071424
}