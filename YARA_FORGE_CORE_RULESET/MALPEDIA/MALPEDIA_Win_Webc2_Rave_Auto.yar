rule MALPEDIA_Win_Webc2_Rave_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "ea4a2e95-f571-5243-9ef5-0d9d72800185"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.webc2_rave"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.webc2_rave_auto.yar#L1-L114"
		license_url = "N/A"
		logic_hash = "2cbb2512779b7c01486a2ad87d98dfe34ac5aeaa8fcccabe432ae13b764de599"
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
		$sequence_0 = { 0f8454010000 8b35???????? 8d542414 6a00 }
		$sequence_1 = { 0f84ea000000 8d542414 6a00 52 8d44241a 6a01 }
		$sequence_2 = { 56 68???????? 53 52 ffd7 3bc3 894614 }
		$sequence_3 = { f7d1 49 3bd9 72e5 }
		$sequence_4 = { 8d442418 50 51 e8???????? 85c0 74b1 }
		$sequence_5 = { 895c2448 ffd7 3bc3 894610 7517 }
		$sequence_6 = { 7418 8b742418 46 4f }
		$sequence_7 = { 33c9 33f6 85ed 7e45 8b942414020000 53 }
		$sequence_8 = { 03d1 8bca 894c2414 7872 }
		$sequence_9 = { e8???????? 83c404 ff15???????? 85ff }

	condition:
		7 of them and filesize <57344
}
