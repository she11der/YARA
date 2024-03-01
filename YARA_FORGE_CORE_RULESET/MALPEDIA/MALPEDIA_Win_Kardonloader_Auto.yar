rule MALPEDIA_Win_Kardonloader_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "3f6a3bad-df12-536d-9e36-cfe1dc9fa562"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.kardonloader"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.kardonloader_auto.yar#L1-L127"
		license_url = "N/A"
		logic_hash = "4fe311b419f6bafe180c85c33e9d2d9d1da43b3315ab993943a70f218a823338"
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
		$sequence_0 = { 83e13f c1e806 03c3 8a0490 88443702 8a0419 8b4d0c }
		$sequence_1 = { 5e 8be5 5d c3 6a00 ff15???????? cc }
		$sequence_2 = { e8???????? 83c438 85c0 7405 83c004 }
		$sequence_3 = { 56 ff7508 68???????? e8???????? 85c0 0f8421010000 }
		$sequence_4 = { 50 56 e8???????? 83c40c 894714 b001 5f }
		$sequence_5 = { e8???????? 59 50 8d8550faffff 50 }
		$sequence_6 = { 50 ff35???????? ff35???????? e8???????? 83c438 e9???????? 5f }
		$sequence_7 = { 750b c74704???????? 0fb7720a 6a05 58 663bf0 750e }
		$sequence_8 = { c0e204 8b45fc 880c30 0fb6441f02 8a8018314000 c0e802 }
		$sequence_9 = { 50 8d85e4fdffff 50 8d85e8feffff 68???????? 50 }

	condition:
		7 of them and filesize <57344
}
