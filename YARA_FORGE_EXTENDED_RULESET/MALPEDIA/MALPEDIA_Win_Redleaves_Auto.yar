rule MALPEDIA_Win_Redleaves_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "cc8fab97-eb1b-5c40-a45f-7f10d21eb6b6"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.redleaves"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.redleaves_auto.yar#L1-L162"
		license_url = "N/A"
		logic_hash = "1a1a0a58298bb01a37c19c26700f5fe323706257844254db91cc834d1d6766e7"
		score = 75
		quality = 69
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
		$sequence_0 = { 51 7565 7279 55 7365 7254 }
		$sequence_1 = { 47 657449 7041 64647254 }
		$sequence_2 = { 54 53 51 7565 }
		$sequence_3 = { 9c 894504 9c 9c }
		$sequence_4 = { 83e901 0f85edffffff 89d0 29f8 5f 5b }
		$sequence_5 = { 8d64241c d2c0 8a01 9c }
		$sequence_6 = { 59 89f9 8d64241c d2c0 }
		$sequence_7 = { 8b04b0 8b4018 898588fdffff 8d8578fdffff }
		$sequence_8 = { 8b04b0 ff7018 ff701c 8d85acfdffff }
		$sequence_9 = { 8bec 8b550c 53 8bd9 85d2 7f05 }
		$sequence_10 = { 50 57 ffb610020000 e8???????? }
		$sequence_11 = { 8bec a1???????? 56 85c0 7452 }
		$sequence_12 = { 53 53 6804010000 8d85acfeffff }
		$sequence_13 = { 8b04b0 83c41c 53 53 }
		$sequence_14 = { 50 57 ffb60c020000 e8???????? 83c40c 8b860c020000 }
		$sequence_15 = { 54 9c 60 9c }
		$sequence_16 = { 9c 9c 8f442420 9c }

	condition:
		7 of them and filesize <1679360
}
