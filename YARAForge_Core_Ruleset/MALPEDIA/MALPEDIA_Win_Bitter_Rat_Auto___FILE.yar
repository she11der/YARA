rule MALPEDIA_Win_Bitter_Rat_Auto___FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "48708c16-f954-55fa-bcb7-85a1e067df06"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.bitter_rat"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.bitter_rat_auto.yar#L1-L130"
		license_url = "N/A"
		logic_hash = "cf289391c2e8c84704b0f60fd200159e5bca809a29a5213fda197ca45567e744"
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
		$sequence_0 = { 8bf4 6830750000 ff15???????? 3bf4 e8???????? e9???????? }
		$sequence_1 = { e8???????? 8d856cf8ffff 50 8b8da8feffff 51 e8???????? }
		$sequence_2 = { ff15???????? 3bf4 e8???????? 898574d8ffff 8bf4 8d858cd8ffff }
		$sequence_3 = { 83c408 8d85fcd8ffff 50 e8???????? 83c404 898558d9ffff 8b8558d9ffff }
		$sequence_4 = { ff15???????? 3bf4 e8???????? 8945a0 8bf4 6a01 }
		$sequence_5 = { eb12 8b45f4 83e801 8945f4 8b4de8 83c101 894de8 }
		$sequence_6 = { 89859cdbffff 8b8d9cdbffff 81e9d3070000 898d9cdbffff 83bd9cdbffff15 0f872b020000 8b959cdbffff }
		$sequence_7 = { 8d1c8d00124700 8bf0 83e61f c1e606 8b0b 0fbe4c3104 83e101 }
		$sequence_8 = { e8???????? 83c404 85c0 7420 e8???????? 8bf4 68d0070000 }
		$sequence_9 = { 3b05???????? 0f8688000000 a1???????? d1e0 3945f8 760b 8b4df8 }

	condition:
		7 of them and filesize <1130496
}